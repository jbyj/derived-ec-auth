import express, {Request} from 'express'

import Ajv, {JSONSchemaType, ValidateFunction} from "ajv";

import bodyParser from "body-parser";
import {importJWK, jwtVerify} from "jose";


interface Registration {
    sub: string
    name: {
        given: string,
        family: string
    },
    email: string
    nonce: string
}

interface Login {
    sub: string
    iat: number
    nonce: string
}

interface SignedPayload<T> {
    header: {
        alg: 'ES256',
        jwk: {
            kty: "EC",
            x: string
            y: string
            crv: "P-256",
        }
    }
    payload: T
}

const ajv = new Ajv()

function createPayloadSchema<T>(schema: JSONSchemaType<T>): JSONSchemaType<SignedPayload<T>> {
    return {
        type: "object",
        properties: {
            header: {
                type: "object", properties: {
                    alg: {
                        const: 'ES256'
                    },
                    jwk: {
                        type: 'object',
                        properties: {
                            kty: {const: "EC"},
                            x: {type: 'string'},
                            y: {type: 'string'},
                            crv: {const: "P-256"},
                        }
                    }
                }
            },
            payload: schema as any
        },
        required: ["header", "payload"],
        additionalProperties: false
    } as any
}

const registrationSchema: JSONSchemaType<SignedPayload<Registration>> = createPayloadSchema<Registration>({
    type: 'object',
    properties: {
        sub: {type: 'string'},
        name: {
            type: 'object',
            properties: {
                given: {type: 'string'},
                family: {type: 'string'},
            },
            required: ["given", "family"]
        },
        email: {type: 'string'},
        nonce: {type: 'string'},
    },
    required: ["sub", "name", "email", "nonce"]
})
const loginSchema: JSONSchemaType<SignedPayload<Login>> = createPayloadSchema<Login>({
    type: 'object',
    properties: {
        sub: {type: 'string'},
        iat: {type: 'number', minimum: 0},
        nonce: {type: 'string'},
    },
    required: ["sub", "nonce", "iat"]
})

const validateRegistration = ajv.compile(registrationSchema)
const validateLogin = ajv.compile(loginSchema)


async function validateAndRetrieve<T>(req: Request, validator: ValidateFunction<SignedPayload<T>>): Promise<{ payload: T, publicKey: string }> {
    // WARNING: We are specifically trusting the key passed in the JWT on purpose, that is the public key we will use to later authenticate the user.  For most implementations involving JWTs, NEVER DO THIS!  If you do this, it will allow attacks to sign their own keys and you will accept them as valid.
    const token = await jwtVerify(req.body, (header) => importJWK(header.jwk!, header.alg)) // I cannot emphasize enough, this NEVER DO THIS with JWTs.  This is only done because of this very special-case auth scheme

    // Validate payload
    if (!validator({
        payload: token.payload,
        header: token.protectedHeader
    }))
        throw new Error(validator.errors?.map(a => a.message).join(', ')) // Use better errors in production

    // Get public key
    const {x, y} = token.protectedHeader.jwk!
    // This is just how we'll store it, you can pick any format
    const publicKey = x! + '.' + y!

    return {
        publicKey,
        payload: token.payload as any as T
    }
}

interface User {
    id: string,
    publicKey: string,
    name: {
        given: string,
        family: string
    },
    email: string
}

const users: User[] = []
const app = express()

app.use(bodyParser.text({type: 'application/jwt'}))

app.post('/api/register', async (req, res, next) => {
    try {
        const {payload: reg, publicKey} = await validateAndRetrieve(req, validateRegistration)
        if (users.some(u => u.id === reg.sub))
            throw new Error('User already registered') // Use better errors in production

        const user = {
            id: reg.sub,
            name: reg.name,
            email: reg.email,
            publicKey
        }
        users.push(user)

        res.send({
            status: 'success',
            user
        })

    } catch (e) {
        next(e)
    }
})

app.post('/api/login', async (req, res, next) => {
    try {
        const {payload: login, publicKey} = await validateAndRetrieve(req, validateLogin)
        const user = users.find(user => user.id === login.sub && user.publicKey == publicKey)

        if (!user)
            throw new Error('Invalid username/password.') // Use better errors in production

        // Success, send things
        res.send({
            status: 'success',
            user: user
        })

    } catch (e) {
        next(e)
    }
})

app.use((err: any, req: any, res: any, next: any) => {
    if (err) {
        // Use real errors and error handling, this just assumes everything is a user request error
        res.status(400).send({
            error: true,
            message: err.message
        })
    }
    next()
})

const port = 3001
app.listen(port, () => {
    console.log(`Listening on http://localhost:${port}`)
})
