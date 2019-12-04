# stegosaurus
   
   Hide messages within image files. For enabling your inner James Bond.

## preflight requirements

To install all project dependencies, use `pip` on the `requirements.txt` file:

    pip3 install -r requirements.txt

Full parameters & options:
			

    usage: stegosaurus.py [-h] [-e | -d] [-v] -s SOURCE IMAGE [-o OUTPUT FILE]
                                  [-f INPUT FILE] [--input INPUT STRING]
            
            Hide messages within image files.
            
            optional arguments:
              -h, --help            show this help message and exit
              -e, --encode          Encode a string.
              -d, --decode          Decode an image.
              -v, --verbose         Enable verbose logging.
              -s SOURCE IMAGE, --source SOURCE IMAGE
                                    Source image.
              -o OUTPUT FILE, --out OUTPUT FILE
                                    Destination file.
              -f INPUT FILE, --file INPUT FILE
                                    Filepath of data to hide.
              --input INPUT STRING  String to hide.

## encoding

To encode a simple string on the command line, use the following:

    ./stegosaurus.py --encode -v --input "hello friends" -s heavy.png

To encode from a text file, do the following:

    ./stegosaurus.py --encode -v -f declaration_of_independence.txt -s heavy.png

## decoding

To decode a message from an encoded file, do the following:

    ./stegosaurus.py --decode -s encoded.heavy.png

   





