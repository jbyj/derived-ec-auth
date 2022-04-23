import React, {useCallback, useState} from 'react';
import './App.css';
import {Buffer} from 'buffer';
import base64url from "base64url";
import {useForm} from "react-hook-form";

(window as any).Buffer = Buffer;

const EC = require("elliptic").ec;
const ec = new EC("p256");

const subtle = window.crypto.subtle

const stringToArrayBuffer = (str: string) => new TextEncoder().encode(str);

async function derivePbkdf2(value: string, salt: string | ArrayBuffer, iterations: number = 100000): Promise<ArrayBuffer> {
    // Import the value as our key source
    const pwd = await subtle.importKey(
        "raw",
        stringToArrayBuffer(value),
        "PBKDF2",
        false,
        ["deriveKey"]
    );
    // Derive the key from it, using the provided salt
    let key = await subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: typeof salt === 'string' ? stringToArrayBuffer(salt) : salt,
            iterations,
            hash: "SHA-256",
        },
        pwd,
        {name: "hmac", hash: "SHA-256", length: 256},
        true,
        ["sign"]
    );

    // Export the resulting array buffer
    return subtle.exportKey("raw", key)
}

async function ecPairFromPassword(password: string, salt: string): Promise<CryptoKeyPair> {
    // This derives the material to generate the private key from the password using PBKDF2
    const hashed = await derivePbkdf2(password, await derivePbkdf2(salt, window.origin))
    // Generate a keypair from the raw material
    const keyPair = ec.keyFromPrivate(Buffer.from(hashed), "hex");

    // Calculate the public key
    const pubPoint = keyPair.getPublic();
    const x = pubPoint.getX();
    const y = pubPoint.getY();

    // Here is the base jwk object, it's shared between public and private keys
    const jwkBase = {
        kty: "EC",
        x: base64url(x.toBuffer()),
        y: base64url(y.toBuffer()),
        crv: "P-256",
    };

    // Import the private key, adding the necessary JWK props
    const privateKey = await subtle.importKey(
        "jwk",
        {
            ...jwkBase,
            key_ops: ["sign"],
            d: base64url(keyPair.getPrivate().toBuffer())
        },
        {
            name: "ECDSA",
            namedCurve: "P-256",
        },
        true,
        ["sign"]
    );
    // Import the public key, adding the necessary JWK props
    const publicKey = await subtle.importKey(
        "jwk",
        {...jwkBase, key_ops: ['verify']},
        {
            name: "ECDSA",
            namedCurve: "P-256",
        },
        true,
        ["verify"]
    );
    // Return the keypair
    return {
        privateKey,
        publicKey
    }
}

async function createEcJWT(payload: Record<any, any>, pair: CryptoKeyPair) {
    const header = {
        alg: "ES256",
        typ: "JWT",
        jwk: await subtle.exportKey('jwk', pair.publicKey)
    };
    //Strip out some uneeded field
    header.jwk.key_ops = undefined
    header.jwk.ext = undefined

    //Generate JWT
    const jwtStart =
        base64url(Buffer.from(JSON.stringify(header), "utf8") as any) +
        "." +
        base64url(Buffer.from(JSON.stringify({iat: Math.floor(Date.now() / 1000), ...payload}), "utf8") as any);
    const signature = await subtle.sign(
        {
            name: "ECDSA",
            hash: "SHA-256",
        },
        pair.privateKey,
        stringToArrayBuffer(jwtStart)
    );
    return jwtStart + "." + base64url(Buffer.from(signature) as any)
}

const sha256Url = async (str: string) => base64url(Buffer.from(await crypto.subtle.digest('SHA-256', stringToArrayBuffer(str))))

function App() {
    // For really bad nav, just a toggle state
    const [login, setLogin] = useState(false)
    return (
        <div className="App">
            <div>
                {login ? <button onClick={() => setLogin(false)}>Go to Register</button> :
                    <button onClick={() => setLogin(true)}>Go to Login</button>}

            </div>
            <hr/>
            {login ? <Login/> : <Register/>}
        </div>
    );
}

function Login() {

    const {register, handleSubmit} = useForm();
    const loginApi = useCallback(async ({
                                            email,
                                            password
                                        }: { email: string, password: string }) => {
        try {
            const keyPair = await ecPairFromPassword(password, window.origin)

            const jwt = await createEcJWT({
                sub: await sha256Url(email.toLowerCase()),
                nonce: base64url(Buffer.from(crypto.getRandomValues(new Uint8Array(24))))
            }, keyPair)

            const result = await fetch('/api/login', {
                method: 'POST',
                body: jwt,
                headers: {'content-type': 'application/jwt'}
            }).then(a => a.json())
            if (result.error)
                alert(result.message)
            else {
                alert(`Success, ${result.user.name.given}!`)
            }

        } catch (e: any) {
            alert(e.message)
        }
    }, [])

    return (
        <div>
            <form onSubmit={handleSubmit(loginApi as any)}>
                <p><label>Email: <input type={'email'} {...register("email")} /></label></p>
                <p><label>Password: <input type={'password'} {...register("password")} /></label></p>
                <button>Register</button>
            </form>
        </div>
    );
}


function Register() {

    const {register, handleSubmit, reset} = useForm();
    const registerApi = useCallback(async ({
                                               email,
                                               given,
                                               family,
                                               password
                                           }: { email: string, given: string, family: string, password: string }) => {
        try {
            const keyPair = await ecPairFromPassword(password, window.origin)
            // Here is the PEM SPKI for your pleasure
            console.log('-----BEGIN PUBLIC KEY-----\n' + Buffer.from(await subtle.exportKey("spki", keyPair.publicKey)).toString('base64') + '\n-----END PUBLIC KEY-----');

            const jwt = await createEcJWT({
                sub: await sha256Url(email.toLowerCase()),
                name: {
                    given,
                    family
                },
                email,
                nonce: base64url(Buffer.from(crypto.getRandomValues(new Uint8Array(24))))
            }, keyPair)

            const result = await fetch('/api/register', {
                method: 'POST',
                body: jwt,
                headers: {'content-type': 'application/jwt'}
            }).then(a => a.json())
            if (result.error)
                alert(result.message)
            else {
                alert('Registered')
                reset()
            }

        } catch (e: any) {
            alert(e.message)
        }
    }, [reset])

    return (
        <div>
            <form onSubmit={handleSubmit(registerApi as any)}>
                <p><label>Email: <input type={'email'} {...register("email")} /></label></p>
                <p><label>Given Name: <input {...register("given")} /></label></p>
                <p><label>Family Name: <input {...register("family")} /></label></p>
                <p><label>Password: <input type={'password'} {...register("password")} /></label></p>
                <button>Register</button>
            </form>
        </div>
    );
}


export default App;
