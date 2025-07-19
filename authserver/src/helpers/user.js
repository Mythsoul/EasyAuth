import { prisma } from "../config/database.js";

export class Auth { 
       constructor (formData) { 
        this.formData = formData;
       } 
       async DoesUserExist() { 
            const user = await prisma.user.findUnique({
                where: { email : this.formData.email }, 
            });
            return user ? true : false ;
       } 
    
}
