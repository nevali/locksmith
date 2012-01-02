To build Locksmith as a native Windows executable, you'll need a Microsoft C compiler and the binary build of OpenSSL from:

http://www.slproweb.com/products/Win32OpenSSL.html

(Don't download the "light" version - you need the full version which includes the include files and import libraries)

Once everything's installed, run a toolchain command prompt (e.g., Start > Microsoft Visual Studio 2010 Express > Visual Studio Command Prompt (2010)), change to the directory where you extracted the Locksmith sources and run "build" (which itself runs NMAKE on win32.mak).

At present the build is only for Win32, and assumes you have OpenSSL installed to C:\OpenSSL-Win32, but you can alter this path by modifying win32.mak.
