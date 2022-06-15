import _sodium from 'libsodium-wrappers';
import _ from 'lodash';

import { lookupBppById } from './registryApis/index.js';
import { SUBSCRIBER_TYPE } from './constants.js';

const createSigningString = async (message, created, expires) => {
    if (!created) created = Math.floor(new Date().getTime() / 1000).toString();
    if (!expires) expires = (parseInt(created) + (1 * 60 * 60)).toString();

    await _sodium.ready;

    const sodium = _sodium;
    const digest = sodium.crypto_generichash(64, sodium.from_string(message));
    const digest_base64 = sodium.to_base64(digest, _sodium.base64_variants.ORIGINAL);

    const signing_string =
        `(created): ${created}
(expires): ${expires}
digest: BLAKE-512=${digest_base64}`

    return { signing_string, created, expires };
}

const getProviderPublicKey = async (providers, keyId) => {
    try {

        const provider = _.find(providers, ['ukId', keyId]);
        return provider?.signing_public_key || false;

    } catch (err) {
        return false;
    }
}

const lookupRegistry = async (subscriber_id, unique_key_id) => {
    try {

        const response = await lookupBppById({
            type: SUBSCRIBER_TYPE?.BAP,
            subscriber_id: subscriber_id
        });

        if (!response)
            return false;

        const public_key = await getProviderPublicKey(response, unique_key_id);
        if (!public_key)
            return false;

        return public_key;

    } catch (err) {
        return false;
    }
}

const remove_quotes = (a) => {
    return a.replace(/^["'](.+(?=["']$))["']$/, '$1');
}

const split_auth_header = (auth_header) => {
    const header = auth_header.replace('Signature ', '');
    let re = /\s*([^=]+)=([^,]+)[,]?/g;
    let m;
    let parts = {};
    while ((m = re.exec(header)) !== null) {
        if (m) {
            parts[m[1]] = remove_quotes(m[2]);
        }
    }
    return parts;
}

const verifyMessage = async (signedString, signingString, publicKey) => {
    try {

        await _sodium.ready;
        const sodium = _sodium;

        return sodium.crypto_sign_verify_detached(
            sodium.from_base64(signedString, _sodium.base64_variants.ORIGINAL),
            signingString,
            sodium.from_base64(publicKey, _sodium.base64_variants.ORIGINAL)
        );

    } catch (err) {
        return false;
    }
}

const verifyHeader = async (headerParts, body, public_key) => {

    const { signing_string } = await createSigningString(
        JSON.stringify(body),
        headerParts['created'],
        headerParts['expires']
    );
    const verified = await verifyMessage(headerParts['signature'], signing_string, public_key);

    return verified;
}

export const isSignatureValid = async (header, body) => {
    try {
        let isValid = false;

        const headerParts = split_auth_header(header);

        const keyIdSplit = headerParts['keyId'].split('|');
        const subscriber_id = keyIdSplit[0];
        const unique_key_id = keyIdSplit[1];
        const algorithm = keyIdSplit[2];

        console.log(algorithm === headerParts.algorithm);

        if(algorithm === headerParts.algorithm) {
            const public_key = await lookupRegistry(subscriber_id, unique_key_id);

            if (public_key)
                isValid = await verifyHeader(headerParts, body, public_key);
        }
        return isValid;

    } catch (err) {
        return false;
    }
}
