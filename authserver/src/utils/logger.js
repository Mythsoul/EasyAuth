import { contentSecurityPolicy } from "helmet"
import util from 'util'

const formatMessage = (message) => {
    if (typeof message === 'object') {
        return util.inspect(message, { depth: null, colors: true });
    }
    return message;
}

export const logger = { 
    info : (message, data) => { 
        if (data) {
            console.log(`INFO: ${message}`);
            console.log(formatMessage(data));
        } else {
            console.log(`INFO:`, formatMessage(message));
        }
    }
    ,
    error : (message, data) => {
        if (data) {
            console.error(`ERROR: ${message}`);
            console.error(formatMessage(data));
        } else {
            console.error(`ERROR:`, formatMessage(message));
        }
    }
    ,
    warn : (message, data) => {
        if (data) {
            console.warn(`WARN: ${message}`);
            console.warn(formatMessage(data));
        } else {
            console.warn(`WARN:`, formatMessage(message));
        }
    }
    ,
    debug : (message, data) => {
        if (process.env.NODE_ENV === 'development') {
            if (data) {
                console.debug(`DEBUG: ${message}`);
                console.debug(formatMessage(data));
            } else {
                console.debug(`DEBUG:`, formatMessage(message));
            }
        }
    }
    
}
