import { prisma } from "../config/database";
import { logger  } from "../utils/logger";


export class Auth { 
       constructor (formData) { 
        this.formData = formData;
       } 
       async FindUserByEmail(formData) { 
        try {
            const user = await prisma.user.findUnique({
                where: { email }
            });
            return user;
        } catch (error) {
            logger.error(`Error finding user by email: ${email}`, error);
            throw error;
        }
       } 
    
}