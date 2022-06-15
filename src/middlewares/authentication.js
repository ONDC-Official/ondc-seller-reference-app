import { UnauthenticatedError } from '../lib/errors/index.js';
import { isSignatureValid } from '../utils/cryptic.js';
import MESSAGES from '../utils/messages.js';

const authentication = (options) => async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader) {

        const isValid = await isSignatureValid(authHeader, req.body);

        if (isValid)
            next();
        else
            next(new UnauthenticatedError(MESSAGES.LOGIN_ERROR_USER_ACCESS_TOKEN_INVALID));
    }
    else {
        next(new UnauthenticatedError(MESSAGES.LOGIN_ERROR_USER_ACCESS_TOKEN_INVALID));
    }
};

export default authentication;