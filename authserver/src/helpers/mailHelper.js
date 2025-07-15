class MailHelper { 
    constructor (mailService) {
        this.mailService = mailService;
    }
    static async checkEmailFormat (email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            throw new Error('Invalid email format');
        }
        return true;
    }

}

export {MailHelper}; 