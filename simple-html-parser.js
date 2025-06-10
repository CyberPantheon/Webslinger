/**
 * Simple HTML Parser
 * A lightweight HTML parser that doesn't require external dependencies
 */

class SimpleHtmlParser {
  /**
   * Parse HTML string into a simple DOM-like structure
   * @param {string} html - HTML string to parse
   * @returns {object} - Simple DOM-like object
   */
  static parse(html) {
    // Clean up the HTML
    html = html.trim()

    // Create a root element
    const root = {
      tagName: "root",
      attributes: {},
      children: [],
      text: "",

      // Methods for querying
      querySelector: function (selector) {
        return SimpleHtmlParser.querySelector(this, selector)
      },

      querySelectorAll: function (selector) {
        return SimpleHtmlParser.querySelectorAll(this, selector)
      },

      // Method to get attribute
      getAttribute: function (name) {
        return this.attributes[name] || ""
      },
    }

    // Parse the HTML and build the DOM
    SimpleHtmlParser._parseHtml(html, root)

    // Extract text content
    root.text = SimpleHtmlParser._extractText(root)

    return root
  }

  /**
   * Internal method to parse HTML and build DOM
   * @param {string} html - HTML string to parse
   * @param {object} parent - Parent node
   * @returns {number} - Number of characters consumed
   */
  static _parseHtml(html, parent) {
    let i = 0

    while (i < html.length) {
      // Look for opening tag
      if (html[i] === "<") {
        // Check if it's a comment
        if (html.substring(i, i + 4) === "<!--") {
          // Find end of comment
          const commentEnd = html.indexOf("-->", i)
          if (commentEnd !== -1) {
            i = commentEnd + 3
            continue
          }
        }

        // Check if it's a closing tag
        if (html[i + 1] === "/") {
          const closingTagEnd = html.indexOf(">", i)
          if (closingTagEnd !== -1) {
            return closingTagEnd + 1
          }
        }

        // It's an opening tag
        const tagEnd = html.indexOf(">", i)
        if (tagEnd !== -1) {
          // Extract tag name and attributes
          const tagContent = html.substring(i + 1, tagEnd)
          const tagParts = tagContent.split(/\s+/)
          const tagName = tagParts[0].toLowerCase()

          // Create element
          const element = {
            tagName: tagName,
            attributes: {},
            children: [],
            text: "",

            // Methods
            querySelector: function (selector) {
              return SimpleHtmlParser.querySelector(this, selector)
            },

            querySelectorAll: function (selector) {
              return SimpleHtmlParser.querySelectorAll(this, selector)
            },

            getAttribute: function (name) {
              return this.attributes[name] || ""
            },
          }

          // Parse attributes
          for (let j = 1; j < tagParts.length; j++) {
            const attrPart = tagParts[j].trim()
            if (!attrPart) continue

            // Handle attributes with values
            if (attrPart.includes("=")) {
              const [name, ...valueParts] = attrPart.split("=")
              let value = valueParts.join("=")

              // Remove quotes if present
              if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
                value = value.substring(1, value.length - 1)
              }

              element.attributes[name.toLowerCase()] = value
            } else {
              // Boolean attribute
              element.attributes[attrPart.toLowerCase()] = "true"
            }
          }

          // Add element to parent
          parent.children.push(element)

          // Check if it's a self-closing tag
          if (
            tagContent.endsWith("/") ||
            [
              "img",
              "br",
              "hr",
              "input",
              "link",
              "meta",
              "area",
              "base",
              "col",
              "embed",
              "param",
              "source",
              "track",
              "wbr",
            ].includes(tagName)
          ) {
            i = tagEnd + 1
            continue
          }

          // Parse children
          const consumed = SimpleHtmlParser._parseHtml(html.substring(tagEnd + 1), element)
          i = tagEnd + 1 + consumed
        } else {
          i++
        }
      } else {
        // Text content
        let textEnd = html.indexOf("<", i)
        if (textEnd === -1) textEnd = html.length

        const text = html.substring(i, textEnd).trim()
        if (text) {
          parent.children.push({
            tagName: "#text",
            text: text,
            children: [],
          })
        }

        i = textEnd
      }
    }

    return i
  }

  /**
   * Extract text content from an element
   * @param {object} element - Element to extract text from
   * @returns {string} - Text content
   */
  static _extractText(element) {
    if (element.tagName === "#text") return element.text

    let text = ""
    for (const child of element.children) {
      text += SimpleHtmlParser._extractText(child) + " "
    }

    return text.trim()
  }

  /**
   * Find first element matching selector
   * @param {object} element - Element to search in
   * @param {string} selector - CSS-like selector
   * @returns {object|null} - Matching element or null
   */
  static querySelector(element, selector) {
    const elements = SimpleHtmlParser.querySelectorAll(element, selector)
    return elements.length > 0 ? elements[0] : null
  }

  /**
   * Find all elements matching selector
   * @param {object} element - Element to search in
   * @param {string} selector - CSS-like selector
   * @returns {array} - Array of matching elements
   */
  static querySelectorAll(element, selector) {
    // Parse selector
    const parts = selector.split(/\s*,\s*/)
    const results = []

    for (const part of parts) {
      // Handle element[attr] selector
      if (part.includes("[") && part.includes("]")) {
        const tagEnd = part.indexOf("[")
        const tagName = part.substring(0, tagEnd).toLowerCase()
        const attrPart = part.substring(tagEnd + 1, part.indexOf("]"))

        // Parse attribute selector
        let attrName, attrValue
        if (attrPart.includes("=")) {
          ;[attrName, attrValue] = attrPart.split("=")
          // Remove quotes if present
          if (
            (attrValue.startsWith('"') && attrValue.endsWith('"')) ||
            (attrValue.startsWith("'") && attrValue.endsWith("'"))
          ) {
            attrValue = attrValue.substring(1, attrValue.length - 1)
          }
        } else {
          attrName = attrPart
        }

        // Find matching elements
        SimpleHtmlParser._findElementsWithAttribute(element, tagName, attrName, attrValue, results)
      }
      // Handle element.class selector
      else if (part.includes(".")) {
        const [tagName, className] = part.split(".")
        SimpleHtmlParser._findElementsWithClass(element, tagName.toLowerCase(), className, results)
      }
      // Handle element#id selector
      else if (part.includes("#")) {
        const [tagName, id] = part.split("#")
        SimpleHtmlParser._findElementsWithId(element, tagName.toLowerCase(), id, results)
      }
      // Handle simple tag selector
      else {
        SimpleHtmlParser._findElementsByTag(element, part.toLowerCase(), results)
      }
    }

    return results
  }

  /**
   * Find elements with specific attribute
   * @param {object} element - Element to search in
   * @param {string} tagName - Tag name to match
   * @param {string} attrName - Attribute name to match
   * @param {string} attrValue - Attribute value to match (optional)
   * @param {array} results - Array to store results
   */
  static _findElementsWithAttribute(element, tagName, attrName, attrValue, results) {
    if (element.children) {
      for (const child of element.children) {
        if (child.tagName === tagName || tagName === "") {
          const attr = child.attributes && child.attributes[attrName]
          if (attr !== undefined && (attrValue === undefined || attr === attrValue)) {
            results.push(child)
          }
        }

        SimpleHtmlParser._findElementsWithAttribute(child, tagName, attrName, attrValue, results)
      }
    }
  }

  /**
   * Find elements with specific class
   * @param {object} element - Element to search in
   * @param {string} tagName - Tag name to match
   * @param {string} className - Class name to match
   * @param {array} results - Array to store results
   */
  static _findElementsWithClass(element, tagName, className, results) {
    if (element.children) {
      for (const child of element.children) {
        if (child.tagName === tagName || tagName === "") {
          const classAttr = child.attributes && child.attributes.class
          if (classAttr && classAttr.split(/\s+/).includes(className)) {
            results.push(child)
          }
        }

        SimpleHtmlParser._findElementsWithClass(child, tagName, className, results)
      }
    }
  }

  /**
   * Find elements with specific ID
   * @param {object} element - Element to search in
   * @param {string} tagName - Tag name to match
   * @param {string} id - ID to match
   * @param {array} results - Array to store results
   */
  static _findElementsWithId(element, tagName, id, results) {
    if (element.children) {
      for (const child of element.children) {
        if (child.tagName === tagName || tagName === "") {
          const idAttr = child.attributes && child.attributes.id
          if (idAttr === id) {
            results.push(child)
          }
        }

        SimpleHtmlParser._findElementsWithId(child, tagName, id, results)
      }
    }
  }

  /**
   * Find elements by tag name
   * @param {object} element - Element to search in
   * @param {string} tagName - Tag name to match
   * @param {array} results - Array to store results
   */
  static _findElementsByTag(element, tagName, results) {
    if (element.children) {
      for (const child of element.children) {
        if (child.tagName === tagName) {
          results.push(child)
        }

        SimpleHtmlParser._findElementsByTag(child, tagName, results)
      }
    }
  }
}

module.exports = SimpleHtmlParser

