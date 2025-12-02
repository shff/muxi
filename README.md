muxi
====

A minimal multiplexing development server for macOS.

## Getting Started

```bash
brew tap shff/muxi https://github.com/shff/muxi
brew install muxi
```

To turn it on:

```bash
brew services start shff/muxi/muxi
```

To add new domains:

```bash
muxi --host example.com --port 3000
```

The above operation routes https://example.com/ to a localhost server in port 3000.

To remove:

```bash
muxi --host example.com --remove
```

## Permissions and Password Prompts

- **First run:** When you start the server for the first time (for example with `brew services start shff/muxi/muxi`), muxi may install or provision an HTTPS server and create a local TLS certificates. This operations requires administrative privileges, so you will be prompted for your password (via `sudo`) during startup.

- **During Configuration:** muxi needs to update `/etc/hosts` to map configured hostnames to `127.0.0.1`. This modification is performed by the daemon. When it needs to modify `/etc/hosts` you will be prompted for your password so the process can write the system hosts file.

If you prefer to avoid interactive prompts you can pre-authorize sudo:

```bash
sudo muxi --host example.com --port 3000
```

Alternatively, you can add the host to /etc/hosts by yourself, but you still need to configure muxi:

```bash
echo "127.0.0.1 manual.example.com\n" | sudo tee -a /etc/hosts
muxi --host manual.example.com --port 3000
```

## License

```
MIT License

Copyright (c) 2026 Silvio Henrique Ferreira

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
