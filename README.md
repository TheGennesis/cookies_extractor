# cookies_extractor
This script is a cookies extractor, available only for Windows machines.

## Browsers supported
As by now, the script works for the following browsers:
* Google Chrome
* Microsoft Edge
* Opera
* Mozilla Firefox

## To do next
In the upcoming future, I would like to add:
- [ ] Encryption and decryption process for the extracted cookies
- [ ] Brave browser support
- [ ] Mac OS support, with Safari browser too
- [ ] Linux support

## How to use
In order to extract cookies from your browser, you have to:
* Instantiate an object of class `CookiesExtractor`
* Call the `load()` method of the class

At this point you are able to manipulate your cookies. You can use the following methods:
* `cookies_to_file()`
* `cookies_to_json()`
* `cookies_to_server()`
