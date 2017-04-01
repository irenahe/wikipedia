# Wikipedia
A basic Wikipedia page that allows users to enter almost any word (currently only supports numbers, letters, underscore, and hyphen) and start editing the page content.

### User registration
Username and password must be at least 3 characters long. Email address is not required.

### Edit page
User must be logged-in in order to edit any page.

### JSON output
In any page or history page, add '.json' to the end of the URL to get JSON output.
For example, `https://miniwiki-160622.appspot.com/hello.json` will output:
```
{"content": "Hello,\r\nagain!", "lastModified": "Sun Mar 12 22:43:02 2017", "created": "Sun Mar 12 22:43:02 2017", "title": "hello"}
```
Similarly, `https://miniwiki-160622.appspot.com/_history/hello.json` will output:
```
[{"content": "Hello,\r\nagain!", "lastModified": "Sun Mar 12 22:43:02 2017", "created": "Sun Mar 12 22:43:02 2017", "title": "hello"}, {"content": "Hello,\r\nWorld!", "lastModified": "Sun Mar 12 22:41:01 2017", "created": "Sun Mar 12 22:41:01 2017", "title": "hello"}]
```
