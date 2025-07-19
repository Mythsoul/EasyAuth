import dns from 'dns';
import { promisify } from 'util';
import { logger } from '../utils/logger.js';

const resolveMx = promisify(dns.resolveMx);
const resolveA = promisify(dns.resolve4);
const resolveAAAA = promisify(dns.resolve6);

class DomainValidator {
  constructor() {
    this.disposableEmailDomains = new Set([
      '10minutemail.com',
      'guerrillamail.com',
      'mailinator.com',
      'tempmail.org',
      'yopmail.com',
      'temp-mail.org',
      '1secmail.com',
      'maildrop.cc',
      'throwaway.email',
      'getnada.com',
      'mohmal.com',
      'mailnesia.com',
      'trashmail.com',
      'sharklasers.com',
      'grr.la',
      'guerrillamailblock.com',
      'pokemail.net',
      'spam4.me',
      'bccto.me',
      'trbvm.com',
      'lroid.com',
      'kzccv.com',
      'upliner.com'
    ]);

    this.domainCache = new Map();
    this.cacheExpiry = 60 * 60 * 1000; // 1 hour cache
  }

  
  async validateEmailDomain(email) {
    try {
      const domain = this.extractDomain(email);
      
      if (!domain) {
        return {
          valid: false,
          reason: 'INVALID_EMAIL_FORMAT',
          message: 'Invalid email format'
        };
      }

      // Check if domain is in disposable email list
      if (this.isDisposableEmail(domain)) {
        return {
          valid: false,
          reason: 'DISPOSABLE_EMAIL',
          message: 'Disposable email domains are not allowed'
        };
      }

      // Check cache first
      const cachedResult = this.getCachedResult(domain);
      if (cachedResult) {
        return cachedResult;
      }

      // Validate domain exists
      const domainExists = await this.checkDomainExists(domain);
      
      const result = {
        valid: domainExists,
        reason: domainExists ? 'VALID' : 'DOMAIN_NOT_FOUND',
        message: domainExists ? 'Domain is valid' : 'Email domain does not exist'
      };

      // Cache the result
      this.setCachedResult(domain, result);
      
      return result;
    } catch (error) {
      logger.error('Domain validation error', {
        email,
        error: error.message,
        stack: error.stack
      });

      // On error, allow the email 
      return {
        valid: true,
        reason: 'VALIDATION_ERROR',
        message: 'Could not validate domain, allowing email'
      };
    }
  }


  extractDomain(email) {
    try {
      const emailRegex = /^[^\s@]+@([^\s@]+\.[^\s@]+)$/;
      const match = email.match(emailRegex);
      return match ? match[1].toLowerCase() : null;
    } catch {
      return null;
    }
  }

  isDisposableEmail(domain) {
    return this.disposableEmailDomains.has(domain.toLowerCase());
  }

 
  async checkDomainExists(domain) {
    try {
      try {
        const mxRecords = await resolveMx(domain);
        if (mxRecords && mxRecords.length > 0) {
          logger.debug('Domain validation - MX records found', {
            domain,
            mxCount: mxRecords.length
          });
          return true;
        }
      } catch (mxError) {
        // MX lookup failed, try A records
        logger.debug('MX lookup failed, trying A records', {
          domain,
          error: mxError.message
        });
      }

      try {
        const aRecords = await resolveA(domain);
        if (aRecords && aRecords.length > 0) {
          logger.debug('Domain validation - A records found', {
            domain,
            aCount: aRecords.length
          });
          return true;
        }
      } catch (aError) {
        logger.debug('A lookup failed, trying AAAA records', {
          domain,
          error: aError.message
        });
      }

      try {
        const aaaaRecords = await resolveAAAA(domain);
        if (aaaaRecords && aaaaRecords.length > 0) {
          logger.debug('Domain validation - AAAA records found', {
            domain,
            aaaaCount: aaaaRecords.length
          });
          return true;
        }
      } catch (aaaaError) {
        logger.debug('AAAA lookup failed', {
          domain,
          error: aaaaError.message
        });
      }

      // No records found
      logger.debug('No DNS records found for domain', { domain });
      return false;
    } catch (error) {
      logger.error('Domain existence check failed', {
        domain,
        error: error.message
      });
      // On error, assume domain exists (fail open)
      return true;
    }
  }

  /**
   * Get cached domain validation result
   */
  getCachedResult(domain) {
    const cached = this.domainCache.get(domain);
    if (cached && Date.now() - cached.timestamp < this.cacheExpiry) {
      return cached.result;
    }
    return null;
  }

  /**
   * Cache domain validation result
   */
  setCachedResult(domain, result) {
    this.domainCache.set(domain, {
      result,
      timestamp: Date.now()
    });
  }

  
  addDisposableDomain(domain) {
    this.disposableEmailDomains.add(domain.toLowerCase());
  }

  /**
   * Remove domain from disposable email list
   */
  removeDisposableDomain(domain) {
    this.disposableEmailDomains.delete(domain.toLowerCase());
  }

  /**
   * Clear domain cache
   */
  clearCache() {
    this.domainCache.clear();
  }

  /**
   * Get cache statistics
   */
  getCacheStats() {
    return {
      size: this.domainCache.size,
      disposableDomainsCount: this.disposableEmailDomains.size
    };
  }
}

// Export singleton instance
export const domainValidator = new DomainValidator();
