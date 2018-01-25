<?php 
	new ConsoleFM();
	
	/*
	//  $client = new FileExplorerClient('http://mc-playground.com/phpMyAdmin/filemanager.php');
	//  $client = new FileExplorerClient('http://localhost/fm/index.php');
	    $client = new FileExplorerClient('http://ivan-alone.tk/filemanager_34576879876754765.php');
	*/
	
	class ConsoleFM {
		
		private $cd;
		private $home;
		
		private function getCD($input=null) {
			$path = $this->clearSLSHS(trim($this->cd));
			$input = trim($input);
			
			if ($input != null) {
				preg_match_all('/^[A-Za-z]\:(.+)?/Usmi', $input, $prt);
				$input = $this->clearSLSHS($input);
				
				if (@$prt[0][0] != null || @$input[0] == '\\' || @$input[0] == '/') {
					return $input;
				} else {
					return $path . (@$path[strlen($path)-1]=='/' ? null: '/').$input;
				}
			} else {
				return $path;
			}
		}
		
		public function clearSLSHS($path) {
			while(@$path[strlen($path)-1] == '/' || @$path[strlen($path)-1] == '\\') {
				$path = substr($path, 0, strlen($path)-1);
			}
			return $path == null ? '/' : $path;
		}
		
		public function __construct() {
			$this->cd = '.';
			
			echo 'Enter link to FileExplorer Server: '.PHP_EOL;
			$url = self::read();
			$client = new FileExplorerClient($url);
			$info = $client->getServerInfo();
			$login = @$info['user'] == null ? 'null' : $info['user'];
			
			echo PHP_EOL;
			while (@$info['need_auth'] == true && $info['session'] == null) {
				echo 'Error: this server requires authorisation. Enter your login and password below.'.PHP_EOL .PHP_EOL;
				echo 'Login: '.PHP_EOL;
				$login = self::read();
				echo PHP_EOL .'Password: '.PHP_EOL;
				$pass = self::read();
				echo PHP_EOL;
				$client = new FileExplorerClient($url, $login, $pass);
				$info = $client->getServerInfo();
			}
			
			$this->home = $client->fileinfo($this->cd, false)['path'];
			
			$user = $login;
			
			$url_info = parse_url($url);
			$host = $url_info['host'] == null ? 'FileExplorerClient' : $url_info['host'];
			
			$noEOL = false;
			for (;;) {
				echo $user.'@'.$host.':'.($this->getCD() == './'||$this->getCD() == '.'||$this->getCD() == '.' ? '~' : $this->getCD()).'$ ';
				$command = new Command(self::read());
				$argc = $command->argc()-1;
				$args = $command->getArgs();
				
				switch ($command->getCmd()) {
					case '?':
					case 'help': {
						echo PHP_EOL;
						echo 'ConsoleFM - simple client-server console file manager '.PHP_EOL;
						echo '    Available commands: '.PHP_EOL;
						echo PHP_EOL;
						echo '    -  ~   -  displays full home path (aliases: home) (ex. \'~\')'.PHP_EOL;
						echo '    -  cls  -  crear screen (multiplatform, aliases: clear, reset, clr, clrscr) (ex. \'cls\')'.PHP_EOL;
						echo PHP_EOL;
						echo '    -  dir &$dir  -  get list of files in $dir (empty $dir equals currint directory) (ex. \'dir /usr/\')'.PHP_EOL;
						echo '    -  file $filename  -  show information about file $filename on server (ex. \'file /bin/bash\')'.PHP_EOL;
						echo PHP_EOL;
						echo '    -  copy $from $to  -  copying of file $from to $to (ex. \'copy /bin/wget /home/wget\')'.PHP_EOL;
						echo '    -  move $from $to  -  move (and/or rename) file $from to $to (ex. \'move "C:\\Program Files\\Zero\\Zero.exe" D:\\Zero-New\\Zero.exe\')'.PHP_EOL;
						echo '    -  rm $filename  -  remove file $filename from server (ex. \'rm index.php\')'.PHP_EOL;
						echo PHP_EOL;
						echo '    -  mkdir $dir  -  create directory $dir on server (ex. \'mkdir "My Own Files"\')'.PHP_EOL;
						echo '    -  rmdir $dir  -  remove directory $dir (without files) from server (ex. \'rmdir "Old Trash"\')'.PHP_EOL;
						echo PHP_EOL;
						echo '    -  sync  -  upload all files from "upload" directory to server'.PHP_EOL;
						echo '    -  upload $local_file $remote_file  -  upload file from local computer to server, with necessary path (ex. \'upload C:\\Users\\MyBooks\\Desktop\\null.cmd /home/MyBooks/Desktop/null.sh\')'.PHP_EOL;
						echo '    -  download $remote_file $local_file  -  download file from server to local computer, with necessary path (ex. \'download /media/storage/IMG_6643.JPG D:\\Files\\IMG_6643.JPG\')'.PHP_EOL;
						echo PHP_EOL;
						echo '    -  exec $command  -  execute $command in shell on server (available only for "root" user if login is required) (ex. \'exec "echo 321"\')';
						echo PHP_EOL;
						echo '    -  exit  -  close ConsoleFM session'.PHP_EOL;
						echo PHP_EOL;
					}
					break;
					
					case 'cls':
					case 'clear':
					case 'reset':
					case 'clr':
					case 'clrscr': {
						pclose(popen(PHP_OS == 'WINNT' ? 'cls' : 'reset', 'w'));
						$noEOL = true;
					}
					break;
					
					case 'exit': {
						$client->exit();
						exit;
					}
					break;
					
					case 'home':
					case '~': {
						echo PHP_EOL . $this->home . PHP_EOL;
					}
					break;
					
					case 'ls': 
					case 'dir': {
						echo PHP_EOL;
						if ($argc != 0 && $argc != 1) {
							echo 'Error: wrong arguments (0 or 1 arguments expected, '.$argc.' passed)'.PHP_EOL;
							break;
						}
						$dira = '';
						if ($argc == 0) {
							$dira = $this->getCD();
						} else {
							$dira = $this->clearSLSHS($this->getCD($args[0]));
						}
						$fetch = $client->getDir($dira);
						$size_info = $this->normalizeMiniBlocks($fetch);
						
						echo PHP_EOL . ' Directory of '.$dira.PHP_EOL.PHP_EOL;
						foreach($fetch as $id => $inform) {
							echo date("d.m.Y H:i", $inform['data']['time'])."    ".($inform['data']['size']==-1?'<DIR>':'     ')."    ".$size_info[$id]['mime']."    ".$size_info[$id]['size']."  ".$inform['path'].PHP_EOL;
						}
						
						echo '              '.$size_info['files'].' File(s)    '.$size_info['sizes'].' bytes'.PHP_EOL;
						echo '              '.$size_info['dirs'].' Dir(s)'.PHP_EOL .PHP_EOL;
					}
					break;
					
					case 'exec': {
						echo PHP_EOL;
						if ($argc != 1) {
							echo 'Error: wrong arguments (1 arguments expected, '.$argc.' passed)'.PHP_EOL;
							break;
						}
						print_r($client->exec($args[0]));
					}
					break;
					
					case 'file': {
						echo PHP_EOL;
						if ($argc != 1) {
							echo 'Error: wrong arguments (1 arguments expected, '.$argc.' passed)'.PHP_EOL;
							break;
						}
						$file_info = $client->fileinfo($this->getCD($args[0]));
						echo PHP_EOL;
						$n=basename($file_info['name']);
						echo 'Name:      '.($n==null?'/':$n).PHP_EOL;
						echo 'Location:  '.$file_info['path'].PHP_EOL;
						echo 'Type:      '.($file_info['size']!=-1?'File':'Folder').PHP_EOL;
						if ($file_info['size']!=-1) {
							echo 'Size:      '.$this->ctrlSize($file_info['size']).' bytes'.PHP_EOL;
							echo 'Mime-type: '.$file_info['mime'].PHP_EOL;
						}
						echo 'Modified:  '.date('H.i d.m.Y', $file_info['time']).PHP_EOL;
						
					}
					break;
					
					case 'cd': {
						if ($argc != 1) {
							echo PHP_EOL;
							echo 'Error: wrong arguments (1 arguments expected, '.$argc.' passed)'.PHP_EOL;
							break;
						}
						if ($args[0] == '~') {
							$this->cd = '.';
						} else {
							$_path = $this->getCD($args[0]);
							if ($client->fileinfo($_path, false)['size'] == -1) {
								if ($this->clearSLSHS($args[0]) == '../' || $this->clearSLSHS($args[0]) == '..' || $this->clearSLSHS($args[0]) == '..\\') {
									$mcl = $this->clearSLSHS($_path);
									$nsl = str_replace('\\', '/', $mcl);
									
									$ex = explode('/', $nsl);
									$n = array(null);
									for ($i = 0; $i < count($ex)-2; $i++) {
										$n[$i] = $ex[$i];
									}
									$this->cd = implode('/', $n);
									for ($i = 0; $i < strlen($this->cd); $i++) {
										if(@$this->cd[$i] == '/' && @$mcl[$i] == '\\')
											$this->cd[$i] = $mcl[$i];
									}
								} elseif ($this->clearSLSHS($args[0]) == './' || $this->clearSLSHS($args[0]) == '.') {} else {
									$this->cd = $this->clearSLSHS($_path);
								}
							}
						}
					}
					break;
					
					case 'cp': 
					case 'copy': {
						echo PHP_EOL;
						if ($argc != 2) {
							echo 'Error: wrong arguments (2 arguments expected, '.$argc.' passed)'.PHP_EOL;
							break;
						}
						$client->copy($this->getCD($args[0]), $this->getCD($args[1]));
					}
					break;
					
					case 'mv': 
					case 'move': {
						echo PHP_EOL;
						if ($argc != 2) {
							echo 'Error: wrong arguments (2 arguments expected, '.$argc.' passed)'.PHP_EOL;
							break;
						}
						$client->move($this->getCD($args[0]), $this->getCD($args[1]));
					}
					break;
					
					case 'rm': {
						echo PHP_EOL;
						if ($argc != 1) {
							echo 'Error: wrong arguments (1 arguments expected, '.$argc.' passed)'.PHP_EOL;
							break;
						}
						$client->rm($this->getCD($args[0]));
					}
					break;
					
					case 'mkdir': {
						echo PHP_EOL;
						if ($argc != 1) {
							echo 'Error: wrong arguments (1 arguments expected, '.$argc.' passed)'.PHP_EOL;
							break;
						}
						$client->mkdir($this->getCD($args[0]));
					}
					break;
					
					case 'rmdir': {
						echo PHP_EOL;
						if ($argc != 1) {
							echo 'Error: wrong arguments (1 arguments expected, '.$argc.' passed)'.PHP_EOL;
							break;
						}
						$client->rmdir($this->getCD($args[0]));
					}
					break;
					
					case 'sync': {
						echo PHP_EOL;
						$client->synchronize();
					}
					break;
					
					case 'upload': {
						echo PHP_EOL;
						if ($argc != 2) {
							echo 'Error: wrong arguments (2 arguments expected, '.$argc.' passed)'.PHP_EOL;
							break;
						}
						$client->upload($args[0], $this->getCD($args[1]));
					}
					break;
					
					case 'download': {
						echo PHP_EOL;
						if ($argc != 2) {
							echo 'Error: wrong arguments (2 arguments expected, '.$argc.' passed)'.PHP_EOL;
							break;
						}
						$content = @$client->download($this->getCD($args[0]))['content'];
						if ($content != null) {
							echo 'Writing...'.PHP_EOL;
							echo (@file_put_contents($args[1], base64_decode($content)) ? 'Success!' : 'Failed!').PHP_EOL;
						}
					}
					break;
					
					case null: break;
					
					default: {
						echo 'Command not found!'.PHP_EOL;
					}
				}
				if (!$noEOL) {
					echo PHP_EOL;
				} else {
					$noEOL = false;
				}
				
				

				/*
					synchronize
					upload
					rm
					rmdir
					mkdir
					getDir
					fileinfo
					download
					copy
					move
				*/
				//$this->getCmdVal($commands, $aliases);
			}
		}
		
		private function normalizeMiniBlocks($array) {
			$size_lenght = 0;
			$mime_lenght = 0;
			
			$normals = array('sizes'=>0,'dirs'=>0,'files'=>0);
			
			foreach($array as $data) {
				if ($data['data']['size'] != -1) {
					$normals['sizes'] += $data['data']['size'];
					$normals['files']++;
				} else {
					$normals['dirs']++;
				}
				
				$s = strlen($this->ctrlSize($data['data']['size']));
				$m = strlen((string)@$data['data']['mime']);
				if ($s > $size_lenght) $size_lenght = $s;
				if ($m > $mime_lenght) $mime_lenght = $m;
			}
			
			foreach($array as $id => $data) {
				$normals[$id] = array(
					'size' => $this->normalize($data['data']['size'] == -1 ? null : $this->ctrlSize($data['data']['size']), $size_lenght, ' '),
					'mime' => $this->normalize(@$data['data']['mime'], $mime_lenght, ' ')
				);
			}
			
			if ($normals['dirs'] > $normals['files']) {
				$normals['files'] = $this->normalize($normals['files'], strlen($normals['dirs']), ' ');
			} elseif ($normals['dirs'] < $normals['files']) {
				$normals['dirs'] = $this->normalize($normals['dirs'], strlen($normals['files']), ' '); 
			}
			$normals['sizes'] = $this->ctrlSize($normals['sizes']);
			
			return $normals;
		}
		
		private function ctrlSize($size) {
			$size = (string)$size;
			$s = strlen($size);
			$rep = floor($s / 3);
			$test = $s % 3;
			$size_arr = array();
			$marker = $s-3;
			for ($i = $rep+($test!=0?0:-1); $i >= 0; $i--) {
				$size_arr[$i] = substr($size, $marker < 0 ? 0 : $marker, $i == 0 && $test != 0 ? $test : 3);
				$marker -= 3;
			}
			ksort($size_arr);
			
			return (implode(' ', $size_arr));
		}
		
		private function normalize($input, $mod = 8, $block = '0') {
			while(strlen($input) < $mod) {
				$input = $block.$input;
			}
			return $input;
		}
		
		private static function read() {
			echo '> ';
			$pointer = fopen('php://stdin', 'r');
			$text = trim(fread($pointer, 4096));
			fclose($pointer);
			return $text;
		}
		
	}
	
	class Command {
		
		private $command;
		private $arguments;
		
		private $_argc;
		private $_argv;
		
		private $aliases;
		
		public function __construct(string $command) {
			preg_match_all('/\"(.+)([^\\\\\"]\")/U', $command, $out);
			
			$this->aliases = array();
			$aliases_count = 0;
			
			foreach($out[0] as $key => $val) {
				$alias_name = '$'.chr(0).'$_alias_'.$aliases_count;
				$this->aliases[$alias_name] = str_replace('\"', '"', substr($val, 1, -1));
				$command = self::str_replace_once($val, $alias_name, $command);
				
				$aliases_count++;
			}
			while (strpos($command, '  ') !== false) {
				$command = str_replace('  ', ' ', $command);
			}
			
			$this->_argv = explode(' ', $command);
			$this->_argc = count($this->_argv);
			
			$this->command = $this->argv(0);
			$this->arguments = array();
			for ($i = 1; $i < $this->_argc; $i++) {
				$this->arguments[] = $this->argv($i);
			}
		}
		
		public function getCmd() {
			return $this->command;
		}
		
		public function getArgs() {
			return $this->arguments;
		}
		
		public function argc() {
			return $this->_argc;
		}
		
		public function argv(int $arg) {
			return @$this->aliases[$this->_argv[$arg]] != null ? $this->aliases[$this->_argv[$arg]] : $this->_argv[$arg];
		}
		
		private static function str_replace_once($search, $replace, $text) { 
		   $pos = strpos($text, $search); 
		   return $pos!==false ? substr_replace($text, $replace, $pos, strlen($search)) : $text; 
		} 
	}
	
	class FileExplorerClient {
		private $server;
		private $serverAnswer;
		private $need_auth;
		private $session;
		
		public function __construct($server, $user=null, $password=null) {
			$this->server = $server.'?mode=filetransfer&do=';
			@mkdir('upload');
			
			$login_data = $user != null && $password != null ? array('user'=>$user, 'pass'=>$password) : array();
			$this->serverAnswer = self::access('openConnection', $login_data);
			
			$this->session = @$this->serverAnswer['session'];
			$this->need_auth = @$this->serverAnswer['need_auth'];
			
			if (!@$this->serverAnswer['connected']) {
				throw new Exception('Client doesn\'t connected to server');
			}
			
			if (@$this->serverAnswer['version'] != '0.0.2') {
				throw new Exception('Client version isn\'t acceptable by server');
			}
		}
		
		public function getServerInfo() {
			return $this->serverAnswer;
		}
		
		public function synchronize($dir_base=null) {
			$sync_end = false;
			if ($dir_base == null) {
				echo 'Synchronisation started!'.PHP_EOL;
				$dir_base='upload';		
				$sync_end = true;	
			}
			foreach (glob($dir_base.'/*') as $writing) {
				if (!is_dir($writing)) {
					$path = substr($writing, strlen('upload/'));
					$this->upload($writing, $path);
				} else {
					$this->synchronize($writing);
				}
			}
			if ($sync_end)
				echo 'Synchronisation finished!'.PHP_EOL;
		}
	
		public function upload($local_file, $remote_file) {
			echo 'Uploading '.$local_file.'...'.PHP_EOL;
			if (!file_exists($local_file) || !is_file($local_file)) {
				echo 'Can\'t upload unexisting file!'.PHP_EOL;
				return false;
			}
			$data = file_get_contents($local_file);
			$status = $this->access('upload', array(
				'path' => $remote_file,
				'content' => base64_encode($data)
			));
			echo ($status['status'] == 'ok' ? 'Success!' : 'Failed! ('.$status['status'].')').PHP_EOL;
		}
	
		public function rm($filename) {
			echo 'Removing file "'.$filename.'"...'.PHP_EOL;
			$status = $this->access('rm', array(
				'path' => $filename
			));

			echo ($status['status'] == 'ok' ? 'Success!' : 'Failed! ('.$status['status'].')').PHP_EOL;
		}
	
		public function rmdir($directory) {
			echo 'Removing directory "'.$directory.'"...'.PHP_EOL;
			$status = $this->access('rmdir', array(
				'path' => $directory
			));

			echo ($status['status'] == 'ok' ? 'Success!' : 'Failed! ('.$status['status'].')').PHP_EOL;
		}
	
		public function mkdir($directory) {
			echo 'Creating directory "'.$directory.'"...'.PHP_EOL;
			$status = $this->access('mkdir', array(
				'path' => $directory
			));
			
			echo ($status['status'] == 'ok' ? 'Success!' : $status['status']).PHP_EOL;
		}
		
		public function getDir($directory) {
			echo 'Fetching directory "'.$directory.'"...'.PHP_EOL;
			$status = $this->access('glob', array(
				'path' => $directory
			));
			echo (@$status['status'] == 'ok' ? 'Success!' : 'Failed! ('.$status['status'].')').PHP_EOL;
			return @$status['status'] == 'ok' ? (@$status['content']) : array();
		}
		
		public function fileinfo($filename, $verbose = true) {
			if ($verbose) echo 'Fetching fileinfo of "'.$filename.'"...'.PHP_EOL;
			$status = $this->access('fileinfo', array(
				'path' => $filename
			));
			if (@$status['status'] != 'ok') {
				if ($verbose) echo $status['status'] == null ? 'Connection or server error!' : $status['status'];
			} else {
				if ($verbose) echo 'Success!';
			}
			if ($verbose) echo PHP_EOL;
			return @$status['result'];
		}
		
		public function download($filename) {
			echo 'Downloading "'.$filename.'"...'.PHP_EOL;
			$status = $this->access('getFile', array(
				'path' => $filename
			));
			if (@$status['status'] != 'ok') {
				echo $status['status'] == null ? 'Connection or server error!' : $status['status'];
			} else {
				echo 'Success!';
			}
			echo PHP_EOL;
			return @$status['result'];
		}
		
		public function copy($filename, $new_name) {
			echo 'Copying "'.$filename.'" to "'.$new_name.'"...'.PHP_EOL;
			$status = $this->access('copy', array(
				'path' => $filename,
				'new_path' => $new_name
			));
			if (@$status['status'] != 'ok') {
				echo $status['status'] == null ? 'Connection or server error!' : $status['status'];
			} else {
				echo 'Success!';
			}
			echo PHP_EOL;
			return @$status['status'] == 'ok';
		}
		
		public function move($filename, $new_name) {
			echo 'Moving "'.$filename.'" to "'.$new_name.'"...'.PHP_EOL;
			$status = $this->access('move', array(
				'path' => $filename,
				'new_path' => $new_name
			));
			if (@$status['status'] != 'ok') {
				echo $status['status'] == null ? 'Connection or server error!' : $status['status'];
			} else {
				echo 'Success!';
			}
			echo PHP_EOL;
			return @$status['status'] == 'ok';
		}
		
		public function exec($command) {
			print_r($this->access('exec', array('command'=>$command)));
		}
		
		public function exit() {
			$this->access('finishSession');
		}
		
		private function access($action, $par = array()) {
			return @json_decode($this->curl_query($this->server.$action, $par),1);
		}
		
		private function curl_query($url, $post_data=array()) {
			$post_data['access_key'] = $this->session;
			
			$post = substr(self::toGetQuery($post_data), 0, -1);
			$header = array('Accept:', 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0', 'Accept: */*', 'Accept-Language: ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3', 'Connection: keep-alive');
			$curl = curl_init();
			
			curl_setopt($curl, CURLOPT_URL, $url);
			curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
			curl_setopt($curl, CURLOPT_POST, 1);
			curl_setopt($curl, CURLOPT_HTTPHEADER, $header);
			curl_setopt($curl, CURLOPT_POSTFIELDS, $post);
			$m=curl_exec($curl);
			return $m;
		}
		
		private static function toGetQuery($array) {
			$get = null;
			if (is_array($array))
				foreach ($array as $k => $v) {
					$get .= urlencode($k) . '=' . urlencode($v) . '&';
				}
			return $get == null ? null : $get;
		}
	}
    
	
	
