import util from 'util';

const isDevelopment = process.env.NODE_ENV === 'development';
const isProduction = process.env.NODE_ENV === 'production';
const logLevel = process.env.LOG_LEVEL || (isDevelopment ? 'debug' : 'error');

const LOG_LEVELS = {
    debug: 0,
    info: 1,
    warn: 2, 
    error: 3
};

const shouldLog = (level) => {
    return LOG_LEVELS[level] >= LOG_LEVELS[logLevel];
};

const formatMessage = (message) => {
    if (typeof message === 'object') {
        if (isDevelopment) {
            return util.inspect(message, { depth: null, colors: true });
        } else {
            return JSON.stringify(message);
        }
    }
    return message;
};

const getTimestamp = () => {
    return isProduction ? new Date().toISOString() : '';
};

export const logger = {
    debug: (message, data) => {
        if (!shouldLog('debug')) return;
        
        const timestamp = getTimestamp();
        if (data) {
            console.debug(`${timestamp}DEBUG: ${message}`);
            console.debug(formatMessage(data));
        } else {
            console.debug(`${timestamp}DEBUG:`, formatMessage(message));
        }
    },
    
    info: (message, data) => {
        if (!shouldLog('info')) return;
        
        const timestamp = getTimestamp();
        if (data) {
            console.log(`${timestamp}INFO: ${message}`);
            if (isDevelopment || process.env.VERBOSE_LOGS === 'true') {
                console.log(formatMessage(data));
            }
        } else {
            console.log(`${timestamp}INFO:`, formatMessage(message));
        }
    },
    
    warn: (message, data) => {
        if (!shouldLog('warn')) return;
        
        const timestamp = getTimestamp();
        if (data) {
            console.warn(`${timestamp}WARN: ${message}`);
            console.warn(formatMessage(data));
        } else {
            console.warn(`${timestamp}WARN:`, formatMessage(message));
        }
    },
    
    error: (message, data) => {
        if (!shouldLog('error')) return;
        
        const timestamp = getTimestamp();
        if (data) {
            console.error(`${timestamp}ERROR: ${message}`);
            console.error(formatMessage(data));
        } else {
            console.error(`${timestamp}ERROR:`, formatMessage(message));
        }
    },
    
    security: (message, data) => {
        const timestamp = getTimestamp();
        console.error(`${timestamp}SECURITY: ${message}`);
        if (data) {
            console.error(JSON.stringify(data));
        }
    },
    
    audit: (message, data) => {
        const timestamp = getTimestamp();
        console.log(`${timestamp}AUDIT: ${message}`);
        if (data) {
            console.log(JSON.stringify(data));
        }
    }
};
