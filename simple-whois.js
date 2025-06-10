const net = require("net")
const dns = require("dns").promises

/**
 * Simple WHOIS client that doesn't require external dependencies
 */
class SimpleWhois {
  /**
   * Get WHOIS information for a domain
   * @param {string} domain - Domain to query
   * @returns {Promise<object>} - WHOIS information
   */
  static async lookup(domain) {
    try {
      // Clean up domain
      domain = domain.trim().toLowerCase()

      // Remove protocol and path
      if (domain.startsWith("http://")) domain = domain.substring(7)
      if (domain.startsWith("https://")) domain = domain.substring(8)
      domain = domain.split("/")[0]

      // Get TLD
      const parts = domain.split(".")
      const tld = parts[parts.length - 1]

      // Get WHOIS server for TLD
      const whoisServer = await this._getWhoisServer(tld)
      if (!whoisServer) {
        return {
          error: `Could not find WHOIS server for TLD: ${tld}`,
          domain,
          text: `No WHOIS server found for ${domain}`,
        }
      }

      // Query WHOIS server
      const whoisData = await this._queryWhoisServer(whoisServer, domain)

      // Parse WHOIS data
      return this._parseWhoisData(whoisData, domain)
    } catch (error) {
      return {
        error: error.message,
        domain,
        text: `Error looking up WHOIS for ${domain}: ${error.message}`,
      }
    }
  }

  /**
   * Get WHOIS server for TLD
   * @param {string} tld - Top-level domain
   * @returns {Promise<string>} - WHOIS server hostname
   */
  static async _getWhoisServer(tld) {
    // Common WHOIS servers for popular TLDs
    const commonServers = {
      com: "whois.verisign-grs.com",
      net: "whois.verisign-grs.com",
      org: "whois.pir.org",
      info: "whois.afilias.net",
      biz: "whois.neulevel.biz",
      io: "whois.nic.io",
      co: "whois.nic.co",
      ai: "whois.nic.ai",
      me: "whois.nic.me",
      dev: "whois.nic.google",
      app: "whois.nic.google",
      uk: "whois.nic.uk",
      ca: "whois.cira.ca",
      au: "whois.auda.org.au",
      de: "whois.denic.de",
      fr: "whois.nic.fr",
      nl: "whois.domain-registry.nl",
      ru: "whois.tcinet.ru",
      us: "whois.nic.us",
      eu: "whois.eu",
      cc: "ccwhois.verisign-grs.com",
      tv: "tvwhois.verisign-grs.com",
      name: "whois.nic.name",
      ws: "whois.website.ws",
      bz: "whois.belizenic.bz",
      mobi: "whois.dotmobiregistry.net",
      pro: "whois.registrypro.pro",
      travel: "whois.nic.travel",
      xxx: "whois.nic.xxx",
      tel: "whois.nic.tel",
      jobs: "jobswhois.verisign-grs.com",
      asia: "whois.nic.asia",
      coop: "whois.nic.coop",
      aero: "whois.aero",
      museum: "whois.museum",
      academy: "whois.donuts.co",
      agency: "whois.donuts.co",
      cloud: "whois.nic.cloud",
      club: "whois.nic.club",
      design: "whois.nic.design",
      digital: "whois.donuts.co",
      email: "whois.donuts.co",
      global: "whois.nic.global",
      guru: "whois.donuts.co",
      life: "whois.donuts.co",
      live: "whois.nic.live",
      news: "whois.nic.news",
      online: "whois.nic.online",
      shop: "whois.nic.shop",
      site: "whois.nic.site",
      space: "whois.nic.space",
      store: "whois.nic.store",
      tech: "whois.nic.tech",
      video: "whois.nic.video",
      xyz: "whois.nic.xyz",
      zone: "whois.donuts.co",
    }

    // Return from common servers if available
    if (commonServers[tld]) {
      return commonServers[tld]
    }

    // Try to query IANA for the WHOIS server
    try {
      return await this._queryIanaWhoisServer(tld)
    } catch (error) {
      console.error(`Error querying IANA for WHOIS server: ${error.message}`)
      return null
    }
  }

  /**
   * Query IANA for WHOIS server
   * @param {string} tld - Top-level domain
   * @returns {Promise<string>} - WHOIS server hostname
   */
  static async _queryIanaWhoisServer(tld) {
    try {
      const whoisData = await this._queryWhoisServer("whois.iana.org", tld)

      // Extract WHOIS server from IANA response
      const match = whoisData.match(/whois:\s+([^\s]+)/i)
      if (match && match[1]) {
        return match[1]
      }

      return null
    } catch (error) {
      console.error(`Error querying IANA: ${error.message}`)
      return null
    }
  }

  /**
   * Query WHOIS server
   * @param {string} server - WHOIS server hostname
   * @param {string} domain - Domain to query
   * @returns {Promise<string>} - WHOIS data
   */
  static _queryWhoisServer(server, domain) {
    return new Promise((resolve, reject) => {
      const client = new net.Socket()
      let data = ""

      client.connect(43, server, () => {
        client.write(domain + "\r\n")
      })

      client.on("data", (chunk) => {
        data += chunk.toString()
      })

      client.on("close", () => {
        resolve(data)
      })

      client.on("error", (err) => {
        reject(err)
      })

      // Set timeout
      client.setTimeout(10000, () => {
        client.destroy()
        reject(new Error(`Connection to ${server} timed out`))
      })
    })
  }

  /**
   * Parse WHOIS data
   * @param {string} data - Raw WHOIS data
   * @param {string} domain - Domain queried
   * @returns {object} - Parsed WHOIS information
   */
  static _parseWhoisData(data, domain) {
    // Extract common fields
    const result = {
      domain,
      text: data,
      registrar: this._extractField(data, ["Registrar:", "Registrar Name:", "Sponsoring Registrar:"]),
      creationDate: this._extractField(data, ["Creation Date:", "Created On:", "Created:", "Registration Date:"]),
      expirationDate: this._extractField(data, [
        "Expiration Date:",
        "Registry Expiry Date:",
        "Expiry Date:",
        "Expires On:",
      ]),
      updatedDate: this._extractField(data, ["Updated Date:", "Last Updated On:", "Last Updated:", "Last Modified:"]),
      nameServers: this._extractNameServers(data),
      status: this._extractStatus(data),
    }

    return result
  }

  /**
   * Extract field from WHOIS data
   * @param {string} data - Raw WHOIS data
   * @param {array} fieldNames - Possible field names
   * @returns {string} - Extracted value
   */
  static _extractField(data, fieldNames) {
    for (const fieldName of fieldNames) {
      const regex = new RegExp(`${fieldName}\\s+([^\\n\\r]+)`, "i")
      const match = data.match(regex)
      if (match && match[1]) {
        return match[1].trim()
      }
    }
    return ""
  }

  /**
   * Extract name servers from WHOIS data
   * @param {string} data - Raw WHOIS data
   * @returns {array} - Name servers
   */
  static _extractNameServers(data) {
    const nameServers = []

    // Try different patterns for name servers
    const patterns = [
      /Name Server:\s+([^\s]+)/gi,
      /Nameserver:\s+([^\s]+)/gi,
      /nserver:\s+([^\s]+)/gi,
      /NS\s+([^\s]+)/gi,
    ]

    for (const pattern of patterns) {
      let match
      while ((match = pattern.exec(data)) !== null) {
        if (match[1] && !nameServers.includes(match[1].toLowerCase())) {
          nameServers.push(match[1].toLowerCase())
        }
      }
    }

    return nameServers
  }

  /**
   * Extract status from WHOIS data
   * @param {string} data - Raw WHOIS data
   * @returns {array} - Status codes
   */
  static _extractStatus(data) {
    const statusCodes = []

    // Try different patterns for status
    const patterns = [/Domain Status:\s+([^\s]+)/gi, /Status:\s+([^\s]+)/gi, /Domain State:\s+([^\s]+)/gi]

    for (const pattern of patterns) {
      let match
      while ((match = pattern.exec(data)) !== null) {
        if (match[1] && !statusCodes.includes(match[1])) {
          statusCodes.push(match[1])
        }
      }
    }

    return statusCodes
  }
}

module.exports = SimpleWhois

