import { contentSecurityPolicy } from "helmet"

export const logger = { 
    info : (message) => { 
        console.log(`INFO: ${message}`);
    }
    ,
    error : (message) => {
        console.error(`ERROR: ${message}`);
    }
    ,
    warn : (message) => {
        console.warn(`WARN: ${message}`);
    }
    ,
    debug : (message) => {
        if (process.env.NODE_ENV === 'development') {
            console.debug(`DEBUG: ${message}`);
        }
    }
    
}