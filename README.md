# SHA1-crack
Application for cracking SHA1 hashed password

Supported passwords contains characters in ranges a-z, A-Z and 0-9. <br>
Run application with first parameter SHA1 hash to find the password. <br>
Syntax example: sha1crack.exe 59b7bc438df4f2c39736f84add54036f2083ef60

You can use switches with application:
- --salt or -S followed by salt string to find password with salt before or after password <br>
  Syntax example: sha1crack.exe --salt thisIsSalt 59b7bc438df4f2c39736f84add54036f2083ef60 <br>
- --input or -I followed by path to text file with input password separated by new line <br>
  Syntax example: sha1crack.exe --input inputFile.txt
- --patern or -P followed by expression that matches password. Supported characters are:
  - character without \ for example A means, that letter A is placed on given position
  - \A - upper case letter
  - \a - lower case letter
  - \d - number
  - ? - any letter or number
  - {x, y} preceeded with one of previous characters - from x to y occurences of given character on given position
  - \* (wildcart) preceeded with one of previous characters - any number of given character <br>
  Syntax example: sha1crack.exe --pattern \am\a{1,2}1\d* 0a4ef2d5951b0b1b01fbf93901825ee4e5a36781
- -MT -application uses multiple threads for hash cracking <br>
Syntax example: sha1crack.exe -MT 59b7bc438df4f2c39736f84add54036f2083ef60
- --dictionary or -D followed by path to text file with ditionary passwords separated by new line that are verified at the beggining of password cracking<br>
  Syntax example: sha1crack.exe --dictionary dictionaryFile.txt 59b7bc438df4f2c39736f84add54036f2083ef60 <br>

Switches can be combined. 
  

  
                  
