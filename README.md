# Database Questions

**1.**

    SELECT count(*) FROM Customers WHERE Country='Germany';

**2.**

    SELECT COUNT(CustomerID), Country
    FROM Customers
    GROUP BY Country
    HAVING COUNT(CustomerID) >= 5
    ORDER BY COUNT(CustomerID) DESC;

**3.**

    SELECT 
    c.CustomerName, 
    COUNT(o.OrderID) AS OrderCount,
    FORMAT(MIN(o.OrderDate), "yyyy-mm-dd") AS FirstOrder,
    FORMAT(MAX(o.OrderDate), "yyyy-mm-dd") AS LastOrder
    FROM Orders AS o
    INNER JOIN Customers AS c ON o.CustomerID = c.CustomerID
    GROUP BY c.CustomerID, c.CustomerName
    ORDER BY MAX(o.OrderDate) DESC;



# JavaScript/TypeScript Questions
**1.1.** 

    function titleCase(str) {
        return str
            .toLowerCase()  // Convert the entire string to lowercase first
            .split(' ')     // Split the string into an array of words
            .map(word => {
                // Capitalize the first letter of each word and make the rest lowercase
                return word.charAt(0).toUpperCase() + word.slice(1);
            })
            .join(' ');     // Join the words back together with a space
    }
    
    // Test cases:
    console.log(titleCase("I'm a little tea pot")); // "I'm A Little Tea Pot"
    console.log(titleCase("sHoRt AnD sToUt"));     // "Short And Stout"
    console.log(titleCase("SHORT AND STOUT"));     // "Short And Stout"

**1.2.**

    function countWordFrequency(str) {
        // Remove punctuation and convert the string to lowercase
        const cleanedStr = str.replace(/[^\w\s]/g, '').toLowerCase();
    
        // Split the string into words
        const words = cleanedStr.split(/\s+/);
    
        // Create an object to store word frequencies
        const frequency = {};
    
        // Count the occurrences of each word
        words.forEach(word => {
            frequency[word] = (frequency[word] || 0) + 1;
        });
    
        // Sort by frequency in descending order
        const sortedFrequency = Object.entries(frequency)
            .sort((a, b) => b[1] - a[1])  // Sort by frequency count
            .map(entry => `${entry[0]} => ${entry[1]}`);  // Format as "word => count"
    
        return sortedFrequency.join('\n');
    }
    
    // Test case:
    const text = "Four One two two three Three three four  four   four";
    const wordFrequency = countWordFrequency(text);
    console.log(wordFrequency);

**2.**

    function delay(ms) {
      return new Promise(resolve => {
        setTimeout(resolve, ms);
      });
    }
    
    delay(3000).then(() => alert('runs after 3 seconds'));

**2.5**

    // Convert fetchData to return a Promise
    function fetchData(url) {
      return new Promise((resolve, reject) => {
        setTimeout(() => {
          if (!url) {
            reject("URL is required");
          } else {
            resolve(`Data from ${url}`);
          }
        }, 1000);
      });
    }
    
    // Convert processData to return a Promise
    function processData(data) {
      return new Promise((resolve, reject) => {
        setTimeout(() => {
          if (!data) {
            reject("Data is required");
          } else {
            resolve(data.toUpperCase());
          }
        }, 1000);
      });
    }
    
    // Using async/await
    async function run() {
      try {
        const data = await fetchData("https://example.com");
        const processedData = await processData(data);
        console.log("Processed Data:", processedData);
      } catch (err) {
        console.error("Error:", err);
      }
    }
    
    run();


# Website Security Best Practises

	Use HTTPS Everywhere (SSL/TLS)

		Enforce HTTPS using HSTS.

		Redirect all HTTP traffic to HTTPS.

		Use strong SSL certificates from trusted CAs (e.g., Let’s Encrypt).

	Keep Software & Dependencies Updated

		Regularly update your CMS, plugins, libraries, frameworks, and server stack.

		Monitor for known vulnerabilities (e.g., via tools like Dependabot, Snyk).

	Sanitize and Validate All Inputs

		Prevent SQL Injection, XSS, and Command Injection.

		Use parameterized queries and input validation libraries.

	Use Web Application Firewalls (WAF)

		Block malicious traffic, bots, and known attack patterns.

		Cloudflare, AWS WAF, and Sucuri are popular choices.

	Implement Proper Authentication & Authorization

		Enforce strong password policies.

		Use Multi-Factor Authentication (MFA).

		Never store passwords in plain text – hash with bcrypt/scrypt/argon2.

	Limit User Permissions (Principle of Least Privilege)

		Give users the minimum access necessary for their role.

		Avoid using root/admin accounts unless absolutely required.

	Protect Against Cross-Site Scripting (XSS)

		Escape output properly (especially in HTML, JS, and URLs).

		Use Content Security Policy (CSP) headers.

	Prevent Cross-Site Request Forgery (CSRF)

		Use CSRF tokens in forms and critical actions.

		SameSite cookies help mitigate this too.
	
	Use Security Headers
	
	Secure Cookies
	
	Disable Directory Listing

		Prevent access to file listings on the server.

	Use Rate Limiting & Brute Force Protection

		Protect login endpoints.

		Implement CAPTCHA or throttle requests after failed attempts.

	Monitor Logs and Enable Intrusion Detection

		Log important events: logins, failed attempts, file changes, etc.

		Use tools like Fail2Ban, OSSEC, or cloud-based SIEMs.

	Avoid Using Default Admin URLs and Credentials

		Rename /admin, /wp-login, etc. if possible.

		Change all default usernames and passwords immediately.

	Secure Your APIs

		Use API authentication (OAuth2, API keys).

		Rate-limit requests.

		Validate input/output rigorously.
		
	Secure File Uploads

		Validate file types and MIME types.

		Store uploads outside the webroot.

		Rename uploaded files and scan for malware.

	Enforce Secure File Permissions

		Web root files: 644 (rw-r--r--)

		Executables/scripts: 755 (rwxr-xr-x)

		Never use 777.

	Use Environment Variables for Secrets

		Never hardcode credentials or API keys into code.

		Use .env files or secret managers (AWS Secrets Manager, Vault).

	Security Scanning & Pen Testing

		Regularly run vulnerability scans.

		Consider third-party penetration tests.

	Database Security

		Use least privilege access for DB users.

		Disable remote root access.

		Sanitize all DB inputs.
	
	Backup Regularly and Securely

		Automate backups.

		Store them encrypted and offsite.

		Test restore process regularly.

	Use DNSSEC

		Helps prevent DNS spoofing and cache poisoning.

	Security Awareness for Admins and Users

		Educate about phishing, MFA, strong passwords, and common attack patterns.

	Bug Bounty or Responsible Disclosure

		Offer a way for ethical hackers to report vulnerabilities safely.

	Set Up Monitoring & Alerts

		Monitor file changes, login attempts, and unusual traffic patterns.

		Get notified in real-time.


# Website Performance Best Practises

    Use a Content Delivery Network (CDN)

        Serve static assets from edge locations closer to users.

        Reduces latency and load on your origin server.

    Enable Caching

        HTTP caching (Cache-Control, ETag) for browser caching.

        Service workers for offline-first strategies and advanced caching.

    Optimize Images

        Use modern formats like WebP or AVIF.

        Resize and compress images appropriately.

        Lazy-load images (loading="lazy").

    Minify and Bundle Assets

        Minify CSS, JS, and HTML.

        Combine small JS/CSS files to reduce HTTP requests.

    Defer or Async JavaScript

        Prevent render-blocking by deferring or asynchronously loading non-critical JS.

    Reduce Server Response Time

        Optimize backend logic and database queries.

        Use efficient frameworks and lightweight server software (e.g., Nginx over Apache).

    Use HTTP/2 or HTTP/3

        Multiplexing, header compression, and server push improve performance.

    Limit Third-Party Scripts

        External scripts (ads, widgets, trackers) often slow down performance.

        Audit regularly and remove non-essential ones.

    Implement Lazy Loading

        Apply lazy loading to images, videos, and iframe embeds to reduce initial load.

    Compress Assets

        Use GZIP or Brotli compression for text files.
	
	Critical CSS and Preload Key Requests

		Inline critical CSS to improve First Contentful Paint.

		Use <link rel="preload"> for important resources (fonts, hero images, etc.).

	Reduce DOM Complexity

		Avoid deep nesting and excessive DOM elements.

	Avoid Large JavaScript Libraries

		Use lighter alternatives (e.g., Preact over React for simple apps).

		Remove unused code (tree-shaking, code splitting).

	Optimize CSS

		Remove unused CSS (tools like PurgeCSS).

		Split CSS per route/page when possible.



# Golang

    package main
    
    import (
    	"fmt"
    	"regexp"
    	"strings"
    )
    
    func countWordFrequency(text string) {
    	// Convert to lowercase
    	text = strings.ToLower(text)
    
    	// Remove punctuation using regex
    	re := regexp.MustCompile(`[^\w\s]`)
    	cleaned := re.ReplaceAllString(text, "")
    
    	// Split into words
    	words := strings.Fields(cleaned)
    
    	// Count frequencies
    	frequency := make(map[string]int)
    	for _, word := range words {
    		frequency[word]++
    	}
    
    	// Print result
    	for word, count := range frequency {
    		fmt.Printf("%s => %d\n", word, count)
    	}
    }
    
    func main() {
    	text := "Four, One two two three Three three four  four   four"
    	countWordFrequency(text)
    }


# Tools (Rate yourself 1 to 5)
 1. Git (4)
 2. Redis (3)
 3.  VSCode / JetBrains? (4)
 4. Linux? (4)
 5. AWS (3)
 6. EC2 (4)
 7. Lambda (0)
 8. RDS (4)
 9. Cloudwatch (1)
 10. S3 (3)
 11. Unit testing (4)
 12. Kanban boards? (4)

