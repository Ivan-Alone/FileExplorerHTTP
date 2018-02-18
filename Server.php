<?php 
	error_reporting('E_ALL & ~E_NOTICE & ~E_STRICT & ~E_DEPRECATED');
	
	define ('__AUTH_INFO', 'auth.lcf');

	function validateFile($path, $allow_dir = false) {
		if ($path == null) {
			echo '{"path":"null","result":false,"status":"Error: path is empty!"}';
			exit;
		}
		
		if (!file_exists($path)) {
			echo json_encode(
				array(
					'path'=>$path,
					'result'=>false,
					'status'=>'Error: file isn\'t exists!'
				)
			);
			exit;
		}
		if (!$allow_dir && !is_file($path)) {
			echo json_encode(
				array(
					'path'=>$path,
					'result'=>false,
					'status'=>'Error: path isn\'t file!'
				)
			);
			exit;
		}
		validate2AuthFile($path);
	}
	
	function validate2AuthFile($path, $return = false) {
		
		if (file_exists(__AUTH_INFO) && filesize($path) < 2*1024*1024 && @md5_file($path) == @md5_file(__AUTH_INFO)) {
			if ($return) {
				return true;
			} else {
				echo json_encode(
				array(
						'path'=>$path,
						'result'=>false,
						'status'=>'Error: file isn\'t exists!'
					)
				);
				exit;
			}
		}
		return false;
	}
	
	function clearLast($path) {
		$path = trim($path);
		while($path[strlen($path)-1] == '/' || $path[strlen($path)-1] == '\\') {
			$path = substr($path, 0, strlen($path)-1);
		}
		
		return $path;
	}

	function fileInfo($file) {
		$info = array('name'=>$file,'path'=>realpath($file),'size'=>-1,'time'=>filemtime($file));
		if (is_file($file)) {
			if (function_exists('finfo_open')) {
				$data = finfo_open(FILEINFO_MIME_TYPE | FILEINFO_PRESERVE_ATIME);
				$info['mime'] = finfo_file($data, $file);
				finfo_close($data);
			}
			$info['size'] = filesize($file);
		}
		return $info;
	}
	
	function _hash($pass, $salt) {
		return hash('sha256', hash('sha256',$pass.$salt).$salt);
	}
	
	function aloadAuth() {
		$auth_info = array('active_sessions'=>array(),'stored_pwds'=>array());
		$lines = explode("\n", file_get_contents(__AUTH_INFO));
		foreach($lines as $str) {
			$line = explode('@', trim($str));
			switch (count($line)) {
				case 4:
					$auth_info['active_sessions'][] = array('ip' => $line[0], 'key' => $line[1], 'user' => $line[2], 'session' => $line[3]);
				break;
				
				case 3:
					$auth_info['stored_pwds'][] = array('username' => $line[0], 'hash' => $line[1], 'salt' => $line[2]);
				break;
				default: continue;
			}
		}
		return $auth_info;
	}
	
	function astoreAuth($auth_info) {
		$out = '';
		
		foreach ($auth_info['stored_pwds'] as $password) {
			$out .= implode('@', $password)."\n";
		}
		
		foreach ($auth_info['active_sessions'] as $session) {
			$out .= implode('@', $session)."\n";
		}
		
		file_put_contents(__AUTH_INFO, $out);
	}
	
	function generateAccessKey($ip, $user, $hash, $salt) {
		return _hash(_hash($ip.$user.$salt.$hash, time()), time().$ip);
	}
	
	function authorize() {
		$session = null;
		
		if (file_exists(__AUTH_INFO)) {
			$auth_info = aloadAuth();
			
			$username = $_POST['user'];
			$pass = $_POST['pass'];
			
			foreach ($auth_info['stored_pwds'] as $user) {
				if ($username == $user['username'] && _hash($pass, $user['salt']) == $user['hash']) {
					$session = generateAccessKey($_SERVER['REMOTE_ADDR'], $user['username'], $user['hash'], $user['salt']);
					@setcookie('access_key', $session);
					
					$auth_info['active_sessions'][] = array('ip' => $_SERVER['REMOTE_ADDR'], 'key' => $session, 'user' => $user['username'], 'session' => true);
					break;
				}
			}
			
			astoreAuth($auth_info);
		}
		
		return $session;
	}
	
	function unauthorize() {
		if (file_exists(__AUTH_INFO)) {
			$auth_info = aloadAuth();
			
			$key = $_POST['access_key'];
			if ($key == null) {
				$key = @$_COOKIE['access_key'];
			}
			$ip = $_SERVER['REMOTE_ADDR'];
			
			$active = $auth_info['active_sessions'];
			foreach ($active as $addr => $session) {
				if ($session['ip'] == $ip && $session['key'] == $key) {
					unset($auth_info['active_sessions'][$addr]);
					@setcookie('access_key', null);
				}
			}
			
			astoreAuth($auth_info);
		}
	}
	
	function checkAuth($return = false, $onlyFor = null) {
		if (file_exists(__AUTH_INFO)) {
			$auth_info = aloadAuth();
			
			$key = @$_POST['access_key'];
			if ($key == null) {
				$key = @$_COOKIE['access_key'];
			}
			
			$ip = $_SERVER['REMOTE_ADDR'];
			
			foreach ($auth_info['active_sessions'] as $session) {
				if ($session['ip'] == $ip && $session['key'] == $key) {
					if ($onlyFor != null) {
						if ($session['user'] == $onlyFor) {
							return true;
						}
					} else {
						return true;
					}
				}
			}
			if ($return) {
				return false; 
			} else {
				echo json_encode(array(
					'dir' => null,
					'content' => array(),
					'path' => null,
					'status' => 'Auth error, incorrect session!'
				));
				exit;
			}
		}
		return true;
	}
	
	if ($_GET['mode'] == 'filetransfer') {
		
		switch ($_GET['do']) {
			case 'openConnection':
			case 'testConnection': {
				$session = authorize();
				
				echo json_encode(array(
					'connected' => true,
					'version' => '0.0.2',
					'status' => 'ok',
					'user' => @get_current_user(),
					'os' => PHP_OS,
					'need_auth' => file_exists(__AUTH_INFO),
					'session' => $session
					
				));
				exit;
			}
			break;
			case 'upload': {
				checkAuth();
				
				$path = $_POST['path'];
				if(validate2AuthFile($path, true)) {
					echo '{"path":"'.$path.'","status":"Can\'t override this file!"}';
					exit;
				}
				
				$content = base64_decode($_POST['content']);
				
				if ($path == null || $content == null) {
					echo '{"path":"null","dir":".","status":"Error: path or content is empty!"}';
					exit;
				}
				
				$dir = './';
				if (count(explode('/', $path)) != 1) {
					$dir = substr($path, 0, strlen($path)-strlen(basename($path))-1);
					$dir_p = explode('/', $dir);
					for ($i = 0; $i < count($dir_p); $i++) {
						$loc = '';
						for ($j = 0; $j <= $i; $j++) {
							$loc .= $dir_p[$j].'/';
						}
						@mkdir ($loc);
					}
				}
				
				echo json_encode(array(
					'path' => $path,
					'dir' => $dir,
					'status' => @file_put_contents($path, $content)?'ok':'Unexpected error'
				));
			}
			break;
			
			case 'finishSession': {
				checkAuth();
				unauthorize();
			}
			break;
			
			case 'mkdir': {
				checkAuth();
				
				$path = $_POST['path'];
				if ($path == null) {
					echo '{"path":"null","result":false,"status":"Error: path is empty!"}';
					exit;
				}
				
				echo json_encode(
					array(
						'path'=>$path,
						'status'=>@mkdir($path)?'ok':'Error: can\'t create directory!'
					)
				);
			}
			break;
			case 'rm': {
				checkAuth();
				
				$path = $_POST['path'];
				if ($path == null) {
					echo '{"path":"null","result":false,"status":"Error: path is empty!"}';
					exit;
				}
				validate2AuthFile($path);
				echo json_encode(array(
					'path' => $path,
					'status' => @unlink($path)?'ok':'Unexpected removing error'
				));
			}
			break;
			case 'rmdir': {
				checkAuth();
				
				$path = $_POST['path'];
				if ($path == null) {
					echo '{"path":"null","result":false,"status":"Error: path is empty!"}';
					exit;
				}
				echo json_encode(array(
					'path' => $path,
					'status' => @rmdir($path)?'ok':'Unexpected removing error'
				));
			}
			break;
			case 'glob': {
				checkAuth();
				
				$path = $_POST['path'];
				
				if ($path == null) {
					echo '{"path":"null","result":false,"status":"Error: path is empty!"}';
					exit;
				}
				
				$path = clearLast($_POST['path']);
				
				$folder = array();
				
				foreach (glob($path.'/*') as $pth) {
					if (validate2AuthFile($pth, true)) continue;
					$folder[] = array(
						'path' => $pth,
						'data' => fileInfo($pth)
					);
				}
				
				echo json_encode(array(
					'path' => $path,
					'content' => $folder,
					'status' => 'ok'
				));
			}
			break;
			case 'fileinfo': {
				checkAuth();
				
				$path = $_POST['path'];
				validateFile($path, true);
				
				echo json_encode(
					array(
						'path'=>$path,
						'result'=>fileInfo($path),
						'status'=>'ok'
					)
				);
			}
			break;
			case 'copy': {
				checkAuth();
				
				$path = $_POST['path'];
				$pathnew = $_POST['new_path'];
				validateFile($path);
				echo json_encode(array(
					'status' => @copy($path, $pathnew) ? 'ok' : 'Error: copying failed!'
				));
			}
			break;
			
			case 'exec': {
				checkAuth(false, 'root');
				
				$p = popen($_POST['command'], 'r');
				echo json_encode(array(
					'data' => fgets($p),
					'status' => 'ok'
				));
				pclose($p);
			}
			break;

			case 'move': {
				checkAuth();
				
				$path = $_POST['path'];
				$pathnew = $_POST['new_path'];
				validateFile($path, true);
				echo json_encode(array(
					'status' => @rename($path, $pathnew) ? 'ok' : 'Error: moving failed!'
				));
			}
			break;
			case 'getFile': {
				checkAuth();
				
				$path = $_POST['path'];
				validateFile($path);
				
				echo json_encode(
					array(
						'path' => $path,
						'name' => basename($path),
						'result'=>array(
							'size' => filesize($path),
							'content' => base64_encode(file_get_contents($path))
						),
						'status'=>'ok'
					)
				);
			}
			break;
		}
		
		exit;
	}
	
	
	const ALLOW_NONMOZILLA_ICONS = true;

	define (MEDIA_ICON, 'data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAQAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABkAAAAzAAAAMwAAADMAAAAzAAAAMwAAADMAAAAzAAAAMwAAADMAAAAzAAAAHwAAAAAAAAAAAAAAAAAAAAF7e3uT+vr6/u7u7v7l5eX+7e3t/vLy8v719fX+9/f3/vj4+P74+Pj+9/f3/piYmLEAAAADAAAAAAAAAAAAAAABenp6lPj4+P5lZWX+ZmZm/mBgYP5bW1v+WVlZ/mdnZ/6AgID+mZmZ/s/Pz/6Xl5eyAAAAAwAAAAAAAAAAAAAAAXp6epTz8/P+fX19/q6u5f+uruH/2OLZ/8bayP/N0c3/urq6/6Ghof9dXV3+lJSUsgAAAAMAAAAAAAAAAAAAAAF4eHiU7e3t/oODg/7a2vP/VVXd/9fo2f89tkv/qdWv/93Iwf/Yr6P/eHh4/pSUlLIAAAADAAAAAAAAAAAAAAABeHh4lN7e3v6VlZX/3d34/2Vl5v/19fX/fc+I/93o3v/htKb/4b6y/3h4eP6UlJSyAAAAAwAAAAAAAAAAAAAAAXh4eJTDw8P+q6ur/5KS8P+np/P/rua1/17NbP/f7+H/4oRk/+bRyf98fHz+kpKSsgAAAAMAAAAAAAAAAAAAAAF4eHiUlpaW/jIyMv9aWlr/mpqa/5OTk/+np6f/vb29/9XT0f/GxMT/kZGR/o+Pj7IAAAADAAAAAAAAAAAAAAABdnZ2lHR0dP4ZGRn/JSUl/pycnP5kZGT+c3Nz/nh4eP88PDz/i4uL/6ampv6MjIyyAAAAAwAAAAAAAAAAAAAAAXV1dZS1tbX+dXV1/hkZGf60tLT+ZmZm/paWlv6srKz+srKy/ri4uP7Q0ND+hoaGsgAAAAMAAAAAAAAAAAAAAAFzc3OU6urq/urq6v7k5OT+w8PD/np6ev66urr+RkZG/n9/f/6fn5/+0NDQ/nt7e7IAAAADAAAAAAAAAAcAAAAdZWVloczMzP7MzMz+zMzM/t3d3f7l5eX+4uLi/tLS0v6cnJz+fX19/qmpqf5hYWGYAAAAAQAAAAAnJyehS0tL92FhYfuDg4P/fHx8/zo6Ov9oaGj+39/f/tzc3P7Nzc3+pKSk/qWlpf6CgoLMPz8/FAAAAAAAAAAANjY2u0JCQv93d3f/YGBg/2pqav83Nzf/WFhY/tra2v7W1tb+xMTE/sXFxf6rq6vMSEhIFQAAAAAAAAAAAAAAADMzMwU3NzcgaGhoocrKyv7Kysr+yMjI/tXV1f7V1dX+0NDQ/re3t/6Pj4/MSEhIFQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAF5eXmympqbEpaWlxKKiosSgoKDEnJycxJSUlMR2dnaoSEhIFQAAAAAAAAAAAAAAAAAAAAAAAAAAwAMAAIABAACAAQAAgAEAAIABAACAAQAAgAEAAIABAACAAQAAgAEAAIABAAAAAQAAAAMAAAAHAAAADwAAwB8AAA==');
	define (AUDIO_ICON, 'data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAQAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABMAAAArAAAAKgAAACoAAAAqAAAAKgAAACoAAAAqAAAAKgAAACoAAAArAAAAGQAAAAAAAAAAAAAAAAAAAAB2dnaZ/////////////////////////////////////////////////////5+fn7sAAAAAAAAAAAAAAAAAAAAAbW1tlf/////6+vr+9vb2/uzs7P6RkZH+p6en/vDw8P719fX+9/f3/v7+/v+RkZG2AAAAAAAAAAAAAAAAAAAAAGtra5X/////+fn5/vv7+/7W1tb+ExMT/n5+fv7n5+f+9vb2/vX19f78/Pz/kZGRtgAAAAAAAAAAAAAAAAAAAABqamqV//////b29v739/f+/////v////6NjY3+29vb/vb29v7z8/P++vr6/5CQkLYAAAAAAAAAAAAAAAAAAAAAampqlf/////29vb+/////nNzc/6Kior+T09P/pycnP75+fn+8PDw/vj4+P+QkJC2AAAAAAAAAAAAAAAAAAAAAGpqapX/////+fn5/sDAwP5/f3/+sbGx/pycnP55eXn+8/Pz/vDw8P729vb/jIyMtgAAAAAAAAAAAAAAAAAAAABqamqV//////f39/68vLz+fHx8/nBwcP5UVFT+Nzc3/vv7+/7t7e3+8vLy/4mJibYAAAAAAAAAAAAAAAAAAAAAampqlf39/f/x8fH+/////k1NTf7FxcX+l5eX/t/f3/7u7u7+6enp/uzs7P+Ghoa2AAAAAAAAAAAAAAAAAAAAAGhoaJX5+fn/7Ozs/u3t7f7x8fH+RERE/uPj4/7t7e3+5ubm/uLi4v7l5eX/f39/tgAAAAAAAAAAAAAAAAAAAABmZmaV9/f3/+zs7P7r6+v+8fHx/pycnP52dnb+6+vr/uHh4f7d3d3+3d3d/3Z2drcAAAAAAAAAAAAAAAAAAAAQY2Bgn9vb2//S0tL91NTU/e3t7f6Dg4P+zc3N/rS0tP65ubn+qamp/rGxsf9YWFieAAAAAAAAAAA7OzuiQkJC/21tbf5mZmb/VFRU/ycnJ/9eXl79n5+f/lBQUP7T09P+nJyc/qioqP+Ojo7XAAAACAAAAAAAAAAAPj4+wCkpKf9jY2P/WFhY/05OTv8lJSX/RERE/ezs7P7CwsL+xcXF/s/Pz//BwcHXAAAABwAAAAAAAAAAAAAAAAAAAACMjIwUXl5eoN7e3v/X19f/19fX/+bm5v/a2tr/2dnZ/76+vv+bm5vXAAAABwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAQGqqqqrFoqKiwZ6ensGamprBl5eXwZCQkMJubm6pAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAwAMAAMADAADAAwAAwAMAAMADAADAAwAAwAMAAMADAADAAwAAwAMAAMADAACAAwAAAAMAAAAHAACADwAAwB8AAA==');
	define (MOZILLA_ICON, 'data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAQAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACQAAAB0AAAAzAAAAQgAAAEUAAAA4AAAAIwAAAA0AAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAKgIAH3gNE3HPHSCe9hsmsf4ZKrD+Gyec9BUlh9oLD0+WAAAAOQAAAAkAAAAAAAAAAAAAAAAAAAAAAAAADhAQZYogI6f4JDbD/yRCzf8kS9P/JE7X/yRS2f8kT9L/GzWr/g0aapsAAAAaAAAAAAAAAAAAAAAAAAAAAB0jkVYdJ7j+JD3I/yRK0/8kU9r/JFnd/yRe3/8kZeL/JGzk/yRj4P8aTtL+HUPBjAAAAAAAAAAAAAAAAA0NXRMdL7TqJD7K/yRM1v8kV93/JV/f/ypRr/80OGn/MkmL/yV54/8iiez/JHTh/x5Lsf4ESLo/AAAAAAAAAAAgNZ53JD3I/yRM1v8kWN3/JFzd/ypDnv80JlP/SSEd/00hFP9AICH/IqHV/xqs7v8ghtn/Ik6mfAAAAAAAAAAAH0Cv0SRK0/8kVtz/JFjb/yVm4P8ncd7/JXfg/yZit/9QT0z/VycQ/zl2ff8Zxfb/D8j1/xiCzrQAAAAAAAAAABtJxf0kU9r/JV7f/yZByf83WKX/aj8W/3JLG/9kY0b/dEMS/2YxDP9YMx7/Qtj3/yXh/P8YptT1AAAAAAAAAAAaV878JFre/yVl4P8lV9P/NUd9/3FWLP+aWQr/mFgK/4tMBf+ARAb/bDYG/6Pw+v967v7/OZqy/gAAAAIAAAAAIF/U5SVe4P8lauH/JXbk/yKP5/9PZIT/qW8l/7NxG/+qZxT/mVgM/4xOB/+dtKv/lu3+/yKy1eUAAAAAAAAAABxdw5EkZOL/JW3i/yV95f8hheD/P2/X/2qAk//DiRL/vH0U/7VzF/+jZBj/rbKa/4js//8AxuKNAAAAAAAAAAAZUK5GJFjY/yVv4/8jguX/H5Lg/4p3Nv+wjhr/0p0E/9GaCP/FiQ//sHgu/8Ts8P+L4/L/CcPkTQAAAAAAAAAADEzMFB1k2/10d3v9cYBm/0ybp/91i1D/1qYa/+GvIP/cqQv/yJIc/8SlZ/+539//ZK7KtwAAAAAAAAAAAAAAAAAAAAAff+NSv5lPZMGWP/XBkiT/xKU2/+a2QP/rvEf/5bQ3/9OpP//WyJ3vkqmnegAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADbuGAd5L9hmOa/XeTrwF3+7cJd/ui+XuHhvGaRxKZEGgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==');
	{
		$file_types =
			array (
				array(
					'extension' => array (
						'ico'
					),
					'datatype' => 'image/x-icon', 
					'icon' => 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAAYdEVYdFNvZnR3YXJlAHBhaW50Lm5ldCA0LjAuNvyMY98AAAFjSURBVDhPtVDBSgJRFB3MZq3STCHOjFKLICJXMYNKuCtC2okLjRZBtIkoCKJMTKkQ+p75hfmD9rWLNi1n4dzueb5EXzPQog4c3uXec85792n/h+cop40iTxD1rzGisn4e+NmD4disHRKIGj3MpCoBT2Ez27gPnWKJHMeZJ/cwg0aqFXC6MKtGhSIk7iX6WeCrN9ulNcpv1cmsdqiw4U76rIFW2iR6US7TGI5t2yZw2WvRQved0tevpD2SoLFzLGYgtPBIN+Mh8sxKZyowqkeU6n3S4uWLOEH0vufQwiPdjH5MwB0HXHAAn+CPAPZINwMr7A+mK5hui1I3H5S+eiNtwCswl2ozK7B2fgWGfhr4lu2QZVlTFoqrtLJZJ8NrU359e9JnDbTSNoMelTO7/XA2II7QQCtdCm7DpghRXiLIPWFmjVQngNP1k8DP7A3GhtsmEDV6yTfHAZ/U5Z8G1Q/7O2jaFw5S9bl4CE4uAAAAAElFTkSuQmCC'
				), 
				array(
					'extension' => array (
						'jpg',
						'jpeg'
					),
					'datatype' => 'image/jpg', 
					'icon' => 'data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAQAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApaWl/6Wlpf+lpaX/paWl/6Wlpf+lpaX/paWl/6Wlpf+lpaX/paWl/6Wlpf+lpaX/paWl/6Wlpf8AAAAAAAAAAKWlpf////////////////////////////////////////////////////////////////+lpaX/AAAAAAAAAAClpaX//////6tyQv+pc0P/q3lL/7OJX//Annv/ya2Q/9O/p//YxrH/2824/93Qu///////paWl/wAAAAAAAAAApaWl//////92XDb/dV03/3VeOP+Nelz/g3VX/6Cbgv+xq5P/s66W/8C+p/+9u6L//////6Wlpf8AAAAAAAAAAKWlpf//////Q00u/0NSMf9LZz7/WHJJ/2R9VP+Bil//oJtv/66rhf/eyaz//fDk//////+lpaX/AAAAAAAAAAClpaX//////2h7Vf9pgFX/eIdh/66vkf//8N3///Dd///w3f//8N3///Dd///w3f//////paWl/wAAAAAAAAAApaWl//////++vaL/39Gw///rzP//7dH//+7U///auv//4MT//+rR///t1v//5Mj//////6Wlpf8AAAAAAAAAAKWlpf///////rB6///Rq///2LP//sGX//65if/+sHr//rB6//6wev/+sHr//rB6//////+lpaX/AAAAAAAAAAClpaX///////6fZP/+n2T//p9k//6fZP/+n2T//p9k//6fZP/+n2T//p9k//6fZP//////paWl/wAAAAAAAAAApaWl/////////////////////////////////////////////////////////////////6Wlpf8AAAAAAAAAAKWlpf+lpaX/paWl/6Wlpf+lpaX/paWl/6Wlpf+lpaX/paWl/6Wlpf+lpaX/paWl/6Wlpf+lpaX/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA//8AAP//AAD//wAAgAEAAIABAACAAQAAgAEAAIABAACAAQAAgAEAAIABAACAAQAAgAEAAIABAAD//wAA//8AAA=='
				),
				array(
					'extension' => array (
						'gif'
					),
					'datatype' => 'image/gif', 
					'icon' => MOZILLA_ICON
				),
				array(
					'extension' => array(
						'php',
						'xml',
						'txt',
						'css',
						'lcf'
					), 
					'datatype' => 'text/html', 
					'icon' => 'data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAQAQAAAAAAAAAAAAAAAAAAAAAAABbW1v/WVlZ/1lZWf9ZWVn/WVlZ/1lZWf9ZWVn/WVlZ/1lZWf9ZWVn/WVlZ/1lZWf9bW1v/AAAAAAAAAAAAAAAAW1tb//j6+P38/fz+/P38/v39/f79/f3+/f39/f39/f39/f38/f39/P////v////2XFxc/wAAAAAAAAAAAAAAAF5eXv/7/fv/FFYW/wBHAf8ARwH/AEcB/wBHAf8ARwH/AEcB/wBHAf8UVhb//f78/19fX/8AAAAAAAAAAAAAAABgYGD/+/78/zNsNP8ntUT/J7VE/ye1RP8ntUT/Y7al/ylASP9Tpcv/M2w0//z+/P9jY2P/AAAAAAAAAAAAAAAAY2Nj//v+/P9Xh1j/MdB0/zHQdP8x0HT/MdB0/3LZrv9Spcz/AHbF/2SYiP/8/v3/ZmZm/wAAAAAAAAAAAAAAAGVlZf/8/v3/gKSB/zrdof863aH/Ot2h/zrdof863aH/Fcj4/wOo6/8Kdb3//f7+/2pqav8AAAAAAAAAAAAAAABoaGj//P/+/6fAqP9B4bn/QeG5/0Hhuf9B4bn/QeG5/1rkxf8FwP7/AHbH/5HD4v9tbW3/AAAAAAAAAAAAAAAAampq//z//v/L2sz/lt7S/5be0v+W3tL/lt7S/5be0v+W3tL/Mc34/wOv8P8Abb7/cXFx/wAAAAAAAAAAAAAAAG1tbf/9/v7/6vDq/2To3f9k6N3/ZOjd/2To3f9k6N3/ZOjd/2To3f8FwP7/AHrJ/1qPsP8AAAAAAAAAAAAAAABvb2///v////Hu5//l4NT/5eDU/+Xg1P/l4NT/5eDU/+Xg1P/l4NT/W9T5/wO39/8Abb//4ev1GgAAAAAAAAAAcnJy/////////////v79//7+/f/+/v3//v79//7+/f/+/v3//v79//////8Fwf7/AIPN/xZ8wekAAAAAAAAAAHR0dP//////7Onh/+Xg1P/l4NT/5eDU/+Xg1P/l4NT/gYGB/4CAgP+AgID/Uq7L/wO2+P8AbMD/3+fvIAAAAAB3d3f///////39/P///////////////////////Pv6/4CAgP/9/f3//f39/4CAgP4Mwfz+T4+q/4t9ddIAAAAAeXl5//////+Wlpf/9/X0/5OTlP/18/L/k5OU//Lv7f+AgID//f39/4CAgP6Dg4Nd7+PgU8yplP9xWE3/zcfCXHx8fP+3t7f/////KLq6uv////8ourq6/////yi6urr/gICA/4CAgP6Dg4NdAAAAAAAAAACwqL+5HRiE/wAAc/+AgID/gICA/56entOBgYH/np6e1oGBgf+enp7WgYGB/4GBgf+BgYFJAAAAAAAAAAAAAAAA39/vEAYJj/8AAHL/AAcAAAAHAAAABwAAAAcAAAAHAAAABwAAAAcAAAAHAAAABwAAAAMAAAADAAAAAQAAAAEAAAAAAAAAGAAAADgAAA=='
				),
				array(
					'extension' => array(
						'html',
						'htm'
					), 
					'datatype' => 'text/html', 
					'icon' => 'data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAQAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGtra5F0dHTmdHR05nR0dOZ0dHTmdHR05nR0dOZ0dHTmdHR05nR0dOZ0dHTma2trkQAAAAAAAAAAAAAAAAAAAAB5eXnm/f39//39/f/9/f3//f39//39/f/9/f3//f39//39/f/9/f3//f39/3l5eeYAAAAAAAAAAAAAAAAAAAAAgYGB5v39/f/4+Pj/8fHw/9PS0f/JyMf/ysjH/9DPzv/s7ez/9/f3//39/f+BgYHmAAAAAAAAAAAAAAAAAAAAAImJieb8/Pz/6Ofn/7Kwuv9XUp7/QUOh/0JMof9OVKf/paa4/+ro6P/8/Pz/iYmJ5gAAAAAAAAAAAAAAAAAAAACRkZHm+fj4/56kvv8qM7D/JErU/yRa3v8kauP/JHXn/yVr2P+eqMP/+fn5/5GRkeYAAAAAAAAAAAAAAAAAAAAAlJSU5vX09f84ULr/JEjT/yRb3v8zWKb/Ujk9/yyIw/8RwvT/MH7M//T09P+UlJTmAAAAAAAAAAAAAAAAAAAAAJmZmeby8vL/KFrT/yRY3v8nQ8X/SmyN/1Z7c/92Qg7/geb4/0LP8//y8vH/mZmZ5gAAAAAAAAAAAAAAAAAAAACcnJzm8vLy/yKK8P8lYuD/M2/E/6NxLf+ybxz/o2AN/5/X1/+J5fX/8vLy/5ycnOYAAAAAAAAAAAAAAAAAAAAAnp6e5vPz8/8sguD/JWfj/yWE5v9Zjsj/0psH/8mOEf/SwaL/btfh//T09P+enp7mAAAAAAAAAAAAAAAAAAAAAKGhoeb29vX/S4rb/zqM2/9YhKn/ya0n/+y8Rf/erSf/3+LR/7vY3P/5+Pj/oaGh5gAAAAAAAAAAAAAAAAAAAAClpaXm+/v7/+fr8f/fzrP/5r5o//LKbv/zy3D/5sVs/+PWuv/19fX/+/v7/6WlpeYAAAAAAAAAAAAAAAAAAAAAp6en5v7+/v/7+/z/+Pf3//Tz9P/w8fH/8PDw//P09P/49/j/5OLi/+Hg4P6XlZXjAAAAAAAAAAAAAAAAAAAAAKqqqub+/v7//P38//z8/f/8/fz//fz9//z8/P/8/Pz/t7Wz/7e1s/+6uLf/o6Oi5wAAAAAAAAAAAAAAAAAAAACrq6vm/v7+//z8/P/8/fz//P38//z8/P/8/P3//f38/7SysP77+/v/rKuq8Kurq4cAAAAAAAAAAAAAAAAAAAAAr6+v5v7+/v/+/v7//v7+//7+/v/+/v7//v7+//f39/6+vbv/ra2s762trYcAAAAAAAAAAAAAAAAAAAAAAAAAAK2trYewsLDmsLCw5rCwsOawsLDmsLCw5rCwsOawsLDdsLCw5q2trYcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=='
				),
				array(
					'extension' => array(
						'rar',
						'7z',
						'zip',
						'tar',
						'gz'
					), 
					'datatype' => 'application/octet-stream', 
					'icon' => 'data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAQAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/Pz//AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAAAAAAAAAAAAAAqKir/4NvZ/0FmAP8AgID/AE0Y/wBNGP8ATRj/AE0Y/wBNGP8ATRj/AE0Y/wBNGP8ATRj/ADUQ/wAAAAAqKir/4NvZ//////9HbwD/ALm5/1mKAP9XiAD/V4gA/1eIAP9XiAD/V4gA/1eIAP9WhwD/UoMA/wAAAP8lJSX/0s/O///9/P/Mx8X/UoMA///////h9bv/ze+M/8Lrcf+66V3/uOhY/67lQf+l4iv/m98V/5LcAP8ANRD/sa6t///7+P/Vz8v/Kioq/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAAAAAAAADMx8X/AAAA/+Db2f+ITAD/AICA/2Y7AP9mOwD/ZjsA/2Y7AP9mOwD/ZjsA/2Y7AP9mOwD/ZjsA/08xAP+mo6L/AAAA/+Db2f//////p1cA/x3Fxf+nVwD/p1cA/6JWAP+fVQD/n1UA/5xVAP+WUwD/llMA/5RTAP8AAAD/JSUl/9LPzv///fz/zMfF/7ViBf///////+Sw///dpP//15j//9GN///Lgf//xXX//79p//+5Xv//s1L/TzEA/7Gurf//+/j/1c/L/yoqKv8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAAAAAAAAzMfF/wAAAP/g29n/GhNc/wCAgP8AAE//AABP/wAAT/8AAE//AABP/wAAT/8AAE//AABP/wAAT/8AAE//pqOi/wAAAP/g29n//////x8Zbv8dxcX/WQGS/1kBkv9ZAZL/WQGS/1kBkv9ZAZL/WQGS/1kBkv9SAY3/AABP/yUlJf/Sz87///38/8zHxf9SAYb///////C+///lo///3pX//9eH///SfP//0Hj//8pr///AYvT/tVno/xoTXP+xrq3///v4/9XPy/8XEVP/YQma/2cPoP9hCZr/Zw+g/2EJmv9nD6D/YQma/2cPoP9hCZr/XgeV/1IBhv8YE2L/AAAAAMzHxf8XEVP/SgF5/wCRkf8A0dH/AJaW/0UEfv9OAoT/SgF5/04ChP9KAXn/TwGB/zgJdv8XEVP/AAAAAKajov8XEVP/Hxlu/wCWlv8A0dH/AJGR/x8Zbv8rE3P/Jg9q/ysTc/8mD2r/KxNz/yYPav8XEVP/AAAAAAAAAAAgDlP/GhNc/xgTYv8YE2L/GBNi/xgTYv8YE2L/GBNi/xgTYv8YE2L/GBNi/xoTXP8AHFf/AAAAAAAAAAAAAAAA4AEAAMAAAACAAAAAAAAAAAABAACAAAAAAAAAAAAAAAAAAQAAgAAAAAAAAAAAAAAAAAAAAIABAAAAAwAAAAcAAA=='
				),
				array(
					'extension' => array(
						'pdf'
					), 
					'datatype' => 'application/pdf', 
					'icon' => MOZILLA_ICON
				),
				array(
					'extension' => array(
						'exe',
						'com'
					), 
					'datatype' => 'application/octet-stream', 
					'icon' => 'data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAQAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJaRjv+WkY7/lpGO/5aRjv+WkY7/lpGO/5aRjv+WkY7/lpGO/5aRjv+WkY7/lpGO/5aRjv+WkY7/lpGO/5aRjv+WkY7//v7+//7+/v/9/f3/+/v7//n5+f/39/f/9PT0//Ly8v/w8PD/7e3t/+vr6//o6Oj/5+fn/+Xl5f+WkY7/lpGO//7+/v/+/v7//f39//v7+//5+fn/9/f3//T09P/09PT/8vLy/+/v7//t7e3/6urq/+jo6P/m5ub/lpGO/5aRjv/+/v7/hpxV/4GhWf99p13/d6xh/3OwZf/29vb/zMvJ/8zLyf/My8n/zMvJ/+zs7P/q6ur/5+fn/5aRjv+WkY7//v7+/4yTT/+ImVP/g59X/3+kW/96qV//+Pj4//X19f/z8/P/8/Pz//Dw8P/u7u7/6+vr/+np6f+WkY7/lpGO//7+/v+SiEr/jo9N/4qWUf+GnFX/gaFZ//r6+v/My8n/zMvJ/8zLyf/My8n/8PDw/3uoXv/r6+v/lpGO/5aRjv/+/v7/l3xE/5SDSP+Qi0v/jJNP/4iZU//7+/v/+fn5//f39//39/f/9PT0//Ly8v+KllH/7e3t/5aRjv+WkY7//v7+/5xyP/+ZeUL/lYBG/5KISv+Oj03//Pz8/8zLyf/My8n/zMvJ/8zLyf/09PT/ln5F/+7u7v+WkY7/lpGO//7+/v+fajz/nW8+/5p1Qf+XfET/lINI//39/f/9/f3//Pz8//r6+v/4+Pj/9fX1/59qPP/w8PD/lpGO/5aRjv/+/v7//v7+//7+/v/+/v7//v7+//7+/v/9/f3//f39//z8/P/6+vr/+Pj4//X19f/z8/P/8PDw/5aRjv+WkY7/zMvJ/8zLyf/My8n/zMvJ/8zLyf/My8n/zMvJ/8zLyf/My8n/zMvJ/8zLyf/My8n/zMvJ/8zLyf+WkY7/lpGO/9/Y0v/f2NL/39jS/9/Y0v/f2NL/39jS/9/Y0v/f2NL/39jS/5B5aP/f2NL/kHlo/9/Y0v+QeWj/lpGO/5aRjv+WkY7/lpGO/5aRjv+WkY7/lpGO/5aRjv+WkY7/lpGO/5aRjv+WkY7/lpGO/5aRjv+WkY7/lpGO/5aRjv8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA//8AAP//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA//8AAA=='
				),
				array(
					'extension' => array(
						'bat',
						'cmd'
					), 
					'datatype' => 'application/octet-stream', 
					'icon' => 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABGdBTUEAALGPC/xhBQAAAAlwSFlzAAAOwwAADsMBx2+oZAAAABh0RVh0U29mdHdhcmUAcGFpbnQubmV0IDQuMC42/Ixj3wAAAQdJREFUOE+lk9FLg1AUh/2/ewoWFO4lqpcxaWzhY2/2UFuDKbVAx5aV21QmiGNPbfgQ7e7hl+dS466pZAof53Kv5/sdFSUApZCOTqooQ2FBz3jYqVzAGPsXmQJd1yHLMq+/z0RSBXVFgTP14IcRnicuTs/Od85F9gSmafLmdbJWVRWfawbLcfm+2PjDnoDGpmRqpouq7Qc4OKygea1Bu+sijuNsASXR2JRMzR9JvX0aojlYYLTc4NKM0DEeswVEra7wse1ZiP7rFMcXCkarDa7sdwyXjE+SKyDEr3CfJLa+J2hYc7x5wfa+TIEIPfNNu4tWkjx4Gee/g6JsBWVI/cOKkLr5dyB9ATKIRhMURHPrAAAAAElFTkSuQmCC'
				),
				array(
					'extension' => array(
						'doc',
						'docx',
						'docm'
					), 
					'datatype' => 'application/msword', 
					'icon' => 'data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAQAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABiSDT/Ykg0/2JINP9iSDT/Ykg0/2JINP9iSDT/Ykg0/2JINP9iSDT/Ykg0/2JINP9iSDT/AAAAAAAAAAAAAAAAt6KT//ri0v/fuJ7/4LaZ/+K0lf/isZH/5K+M/+WtiP/mq4T/56d+/+ilef/ro3b/Ykg0/wAAAAAAAAAAAAAAALmklf/75tr/++fa//vm2f/65dj/++TW//vi0//54ND/+N3M//nbyf/42sf/6aR6/2JINP8AAAAAAAAAAAAAAAC7ppb/++zi//zs4v/WrpD/1q6Q/9aukP/WrpD/1q6Q/9aukP/43s7/+NvK/+engP9iSDT/AAAAAAAAAAAAAAAAvqiZ//3w6P/98On//fDo//zv5//87eX/++vh//vo3P/65df/+uLT//nezv/mrIX/Ykg0/59YJf+bVCP/mVAi/5dNIP+USR//kkYe/5BEHP+OQRv/jD8b/4s9Gv/WrpD/1q6Q//vl1//64dL/5K6K/2JINP+hWyf///////////////////////////////////////////+NPxr//O/o//zs4v/76Nz/+uTW/+Oxj/9iSDT/pF8o///////AeVH/mUkY///SwP+OOhP/wHlR//+/q///////jkEc/9aukP/WrpD/++rh//vm2v/is5X/Ykg0/6diKv//////wHlR/7BZOv//08H/jzUM/9iad///xLD//////5BEHf/99O//1q6Q//zt5P/76d3/4LaZ/2JINP+pZiv/+PDl/5xKFv+8eiT/mEUU/5REFv+pXzT//8q3//////+SRh7//vby/9aukP/87ub/++rf/964nf9iSDT/rGkt///59f+iViP/9dK4/59PHf//1sT/lD8S/+KqV///////lEof//748//WrpD//PDp//zs4f/duqH/Ykg0/7JpMPj88Ob/pVYf//Tn2v+cShb/5tPE/49AEv+gURn//////5ZMIf/WrpD/1q6Q//3x6f/cvKX/3buk/2NJNf+4azPR7NS9///59P//9e///+7i///l2P//4dL//+HR//////+ZUCL//fj0//317/+3opP/Y0k1/2NJNf9jSTX/vWw1fdKmff3s1L3//PDm///59f///fz/////////////////nFMj//739P/99O//uaSV/9TFuv9jSTX/Yk46GgAAAAC9bDV9uGsz0bNtNP+taS3/qWYr/6diKf+kXyj/olsn/59YJf/+9/P//fTt/8CrnP9jSTX/Yk46GgAAAAAAAAAAAAAAAAAAAADYwrL/18Gx/9bAsP/Uvq7/0r2t/9G6q//Puar/zbao/8u2pv/KtKX/ZlE9GQAAAAAAAAAA4AAAAOAAAADgAAAA4AAAAOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAQAA4AMAAA=='
				),
				array(
					'extension' => array(
						'xls',
						'xlsx'
					), 
					'datatype' => 'application/vnd.ms-excel', 
					'icon' => 'data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAQAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABiSDT/Ykg0/2JINP9iSDT/Ykg0/2JINP9iSDT/Ykg0/2JINP9iSDT/Ykg0/2JINP9iSDT/AAAAAAAAAAAAAAAAt6KT//ri0v/fuJ7/4LaZ/+K0lf/isZH/5K+M/+WtiP/mq4T/56d+/+ilef/ro3b/Ykg0/wAAAAAAAAAAAAAAALmklf/75tr/++fa//vm2f/65dj/++TW//vi0//54ND/+N3M//nbyf/42sf/6aR6/2JINP8AAAAAAAAAAAAAAAC7ppb/++zi/9aukP/WrpD/1q6Q/9aukP/659r/1q6Q/9aukP/WrpD/+NvK/+engP9iSDT/AAAAAAAAAAAAAAAAvqiZ//3w6P/98On//fDo//zv5//87eX/++vh/9aukP/65df/1q6Q//nezv/mrIX/Ykg0/yF8J/8deST/Gnch/xd0Hv8UcRz/Em4Y/w5sFv8MahP/CmgS/wlnEP/87OL/++jd/9aukP/64dL/5K6K/2JINP8jgCr///////////////////////////////////////////8KaBL//O/o//zs4v/76Nz/+uTW/+Oxj/9iSDT/J4It//////8bVhT/G1YU/xtWFP+U3o7/K5dF/zJ9Mv//////DGoT/9aukP/WrpD/1q6Q//vm2v/is5X/Ykg0/ymEMP//////ptin/xtWFP+j4J//Mpxc/zukav+J3YP//////w9sFv/99O///fHq/9aukP/76d3/4LaZ/2JINP8qhjH//////7/mv/+Swov/G1YU/z6wg/+Y35T/lN6P//////8RbRj/1q6Q/9aukP/WrpD/++rf/964nf9iSDT/LYgz/+/47//R7ND/t+O1/zinbP88qHP/o+Gf/57fmv//////FHEc//748//99O//1q6Q//zs4f/duqH/Ykg0/y2HM/ji8eH/5fTk/y6SPP85m1f/G1YU/xtWFP+e1Jr//////xdzHv/WrpD/1q6Q/9aukP/cvKX/3buk/2NJNf8thzPRwd/C/zKCJf8zgS7/0ezQ/6vQqP8bVhT/YIJW//////8adyH//fj0//317/+3opP/Y0k1/2NJNf9jSTX/LIYzfYS7h/7B38L/4vHh/+/47//6/fr/////////////////HXkk//739P/99O//uaSV/9TFuv9jSTX/Yk46GgAAAAAshjN9LYcz0TKKNv8tiDP/K4Yy/ymEMP8ngi3/I34q/yB8J//+9/P//fTt/8CrnP9jSTX/Yk46GgAAAAAAAAAAAAAAAAAAAADYwrL/18Gx/9bAsP/Uvq7/0r2t/9G6q//Puar/zbao/8u2pv/KtKX/ZlE9GQAAAAAAAAAA4AAAAOAAAADgAAAA4AAAAOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAQAA4AMAAA=='
				),
				array(
					'extension' => array(
						'ppt',
						'pptx',
						'pptm'
					), 
					'datatype' => 'application/vnd.ms-powerpoint', 
					'icon' => 'data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAQAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABiSDT/Ykg0/2JINP9iSDT/Ykg0/2JINP9iSDT/Ykg0/2JINP9iSDT/Ykg0/2JINP9iSDT/AAAAAAAAAAAAAAAAt6KT//ri0v/fuJ7/4LaZ/+K0lf/isZH/5K+M/+WtiP/mq4T/56d+/+ilef/ro3b/Ykg0/wAAAAAAAAAAAAAAALmklf/75tr/++fa//vm2f/65dj/++TW//vi0//54ND/+N3M//nbyf/42sf/6aR6/2JINP8AAAAAAAAAAAAAAAC7ppb/++zi//zs4v/WrpD/++rf/9aukP/WrpD/1q6Q/9aukP/WrpD/+NvK/+engP9iSDT/AAAAAAAAAAAAAAAAvqiZ//3w6P/98On//fDo//zv5//87eX/++vh//vo3P/65df/+uLT//nezv/mrIX/Ykg0/0Ncvf9AWLj/O1Gy/zZKqv8xQqL/KjqZ/yUykP8fKoj/GiJ+/xIYdP/WrpD/1q6Q/9aukP/64dL/5K6K/2JINP9GX8D//////9vn/v9ZcsH/LjWR/yw0kv9ZcsH/2+f+//////8WHnr//O/o//zs4v/76Nz/+uTW/+Oxj/9iSDT/SWTD/9vn/v83Ra//W53w/2il8P9mlvD/WZLw/y03sP/b5/7/HCaD/9aukP/WrpD/1q6Q//vm2v/is5X/Ykg0/01pyP9CXbD/XJzw/5LF8P+BtvD/b5nw/2mW8P9akfD/Ql2w/yMvjf/99O///fHq//zt5P/76d3/4LaZ/2JINP9Rb8z/MjmR/5fJ8P+hzfD/i73w/2WR8P9lkfD/baDw/yszkv8qOpn/1q6Q/9aukP/WrpD/++rf/964nf9iSDT/VnXR/yszkv9AefX/UoLu/2iP6P8tTbz/aJfw/3Km8P8rM5L/MkWk//748//99O///PDp//zs4f/duqH/Ykg0/1p71f9CXbD/7fP8//r8///7/f//DQpU/ylX2f9lm/D/Ql2w/zlOr//WrpD/1q6Q/9aukP/cvKX/3buk/2NJNf9dftn/2+f+/zdFr//v9Pz/9/v//w0KVP8xOJH/KymG/8bW9v8/Vrf//fj0//317/+3opP/Y0k1/2NJNf9jSTX/YIPb///////b5/7/Ql2w/zE4kf8xOJH/Rlud/8bW9v//////Q1y9//739P/99O//uaSV/9TFuv9jSTX/6+vhGmCD2/9gg9v/XoDZ/1p61f9WddD/Um/M/01px/9JY8P/Rl+//0Ncvf/+9/P//fTt/8CrnP9jSTX/6+vhGgAAAAAAAAAAAAAAAAAAAADYwrL/18Gx/9bAsP/Uvq7/0r2t/9G6q//Puar/zbao/8u2pv/KtKX/6urqGQAAAAAAAAAA4AAAAOAAAADgAAAA4AAAAOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAA4AMAAA=='
				),
				array(
					'extension' => array(
						'mp3'
					), 
					'datatype' => 'audio/mp3', 
					'icon' => AUDIO_ICON
				),
				array(
					'extension' => array(
						'm3u'
					), 
					'datatype' => 'application/m3u', 
					'icon' => AUDIO_ICON
				),
				array(
					'extension' => array(
						'mp4'
					), 
					'datatype' => 'video/mp4', 
					'icon' => MEDIA_ICON
				),
				array(
					'extension' => array(
						'flv'
					), 
					'datatype' => 'video/flv', 
					'icon' => MEDIA_ICON
				),
				array(
					'extension' => array(
						'mkv'
					), 
					'datatype' => 'video/mkv', 
					'icon' => MEDIA_ICON
				),
				array(
					'extension' => array(
						'avi'
					), 
					'datatype' => 'video/avi', 
					'icon' => MEDIA_ICON
				),
				array(
					'extension' => array(
						'mov'
					), 
					'datatype' => 'video/mov', 
					'icon' => MEDIA_ICON
				),
				array(
					'extension' => array(
						'3gp'
					), 
					'datatype' => 'video/3gp', 
					'icon' => MEDIA_ICON
				),
				array(
					'extension' => array(
						'wav'
					), 
					'datatype' => 'audio/wav', 
					'icon' => AUDIO_ICON
				),
				array(
					'extension' => array(
						'ogg'
					), 
					'datatype' => 'audio/ogg', 
					'icon' => AUDIO_ICON
				),
				array(
					'extension' => array(
						'swf'
					), 
					'datatype' => 'video/swf', 
					'icon' => MEDIA_ICON
				),
				array(
					'extension' => array(
						'png'
					), 
					'datatype' => 'image/png', 
					'icon' => 'data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAQAQAAAAAAAAAAAAAAAAAAAAAAACZmZn/mZmZ/5mZmf+ZmZn/mZmZ/5mZmf+ZmZn/mZmZ/5mZmf+ZmZn/mZmZ/5mZmf+ZmZn/mZmZ/5mZmf+ZmZn/mpqa/+vr6//r6+v/6+vr/+vr6//r6+v/6+vr/+vr6//r6+v/6+vr/+vr6//r6+v/6+vr/+vr6//r6+v/mpqa/5ycnP/t7e3/wcrG/9XV1f+5x8D/t8a+/2Kbsf8Smtj/HYzI/xuEwP8SUHv/EFJ6/xOBvf9Fk7f/7e3t/5ycnP+fn5//7+/v/4KMnP+LjK7/o7K6/7THxv8lVJP/AJPe/wCT7f8FYaL/ERIe/wwKDf8CPWb/DJDV/+/v7/+fn5//oaGh//Hx8f84OHX/FSiX/zI6qf9OU5//FByO/wddwf8Amu//BHCy/xcjMv8SExf/ATZb/wyJzv/x8fH/oaGh/6SkpP/z8/P/JyuO/xUwtP8VMcf/FjfH/xUfrP8KRbT/GZ/R/wqY2/8HeLb/CV6V/wSE0P8Smdn/8/Pz/6SkpP+np6f/9vb2/xAqoP8XNcz/E03L/xdQy/8VH7X/EyGz/yZFmf8IcMb/FJjZ/wqe6P8Oq/T/GaLd//b29v+np6f/qqqq//j4+P8MKpb/D1a4/wxyp/8NZqD/FDu5/w4anP8LDJP/XqC5/zOoxf9Jncf/FaTi/0+jsv/4+Pj/qqqq/6ysrP/6+vr/ChyJ/wpWo/8GzM7/B7rF/wxEn/8KH5D/EBuS/5mruP+Tv8X/wtjU/5/Lzv+iwbv/+vr6/6ysrP+vr6///Pz8/wYVff8PNJP/DJvH/wh5s/8IGZD/BxWS/x0pkf98fbT/9ff3/83n2P/x9/T/4uLi//z8/P+vr6//sbGx//7+/v8HDH3/EB2g/wsoo/8HG5j/BgqM/wUJov9FVab/1uTg/+Hw6P/v9vP/4O/n/8PTy//+/v7/sbGx/7Kysv//////NzyQ/xQnoP8UI6P/EiCR/xYlj/9ka6L/gIOt/7fLw//J2ND/5eXl/8rY0P+7z8b//////7Kysv+ysrL///////////////////////////////////////////////////////////////////////////+ysrL/srKy/7Kysv+ysrL/srKy/7Kysv+ysrL/srKy/7Kysv+ysrL/srKy/7Kysv+ysrL/srKy/7Kysv+ysrL/srKy/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD//wAA//8AAA=='
				),
				array(
					'extension' => array(
						'nvc'
					), 
					'datatype' => 'application/nvc', 
					'icon' => 'data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAQAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAX19fYF5eXr9fX1//Z2dn/29ubv9fX1//Xl5ev19fX2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABfX18gXl5ez2pqav+TkZH/qKWl/62qqv+tqqr/qqen/5WTk/9ramr/Xl5ez19fXyAAAAAAAAAAAAAAAABfX18gXl5e74+Njf/Oycn/tbKy/xt27f8be+7/Gn3u/xt47f+pp6f/0c3N/5GPj/9eXl7vX19fIAAAAAAAAAAAXl5ez5CNjf/SzMz/wr+//6KgoP97enr/e3p6/3t6ev97enr/pKKi/8XCwv/Py8v/kpCQ/15eXs8AAAAAX19fYG1sbP/RzMz/iYeH/3t6ev/k4eH/5uPj/+bj4//m4+P/5uPj/+bj4/97enr/e3p6/9bS0v9sa2v/X19fYF5eXr+npKT/ure3/x1n6v97enr/5OHh/4mJif/f3d3/393d/4mJif/k4eH/e3p6/x1q6/+vra3/nJub/15eXr9fX1//zcnJ/46QmP8dZ+r/e3p6/+Th4f+JiYn/393d/9/d3f+JiYn/5OHh/3t6ev8dauv/e4WV/7u5uf9fX1//ZWRk/9vX1/9ygqT/HWfq/3t6ev/m4+P/iYmJ/4mJif+JiYn/iYmJ/+bj4/97enr/HWrr/1JtoP/GxMT/ZGNj/2VkZP/j4OD/dIWn/x1n6v97enr/0NDQ/8vKyv/Ix8f/xMPD/8vKyv/Kysr/e3p6/x1q6/9XbZj/ysnJ/2RjY/9fX1//4N7e/5qamv8dZ+r/8O/v/8vKyv8dauv/8O/v//Dv7/8dauv/8O/v//Dv7/8dauv/ipKi/8fGxv9fX1//Xl5ev7y7u//S0dH/TmaP//X09P/19PT/9fT0/x1q6/8dauv/HWrr/x1q6/8dauv/HWrr/7+/v/+np6f/Xl5ev19fX2BycnL/+fn5/5uep/8ratL/HHDs/xxw7P/19PT/9fT0//X09P8dauv/HG/s/4OIkP/w7+//b25u/19fX2AAAAAAXl5ez6Wlpf/9/Pz/mp+n/zxrsf8bdu3/G3vt/xp+7v8be+3/9fT0//X09P/j4eH/oJ+f/15eXs8AAAAAAAAAAF9fXyBeXl7vpaWl//n4+P/R0ND/l5yk/3SNqv9yjKj/g46d/7Gurv/i39//nJyc/15eXu9fX18gAAAAAAAAAAAAAAAAX19fIF5eXs98fHz/vby8/+Hf3//j4OD/3tra/9PPz/+urKz/b29v/15eXs9fX18gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAX19fYF5eXr9fX1//b25u/2dnZ/9fX1//Xl5ev19fX2AAAAAAAAAAAAAAAAAAAAAA8A8AAMADAACAAQAAgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAEAAIABAADAAwAA8A8AAA=='
				),
				array(
					'extension' => array(
						'psd'
					), 
					'datatype' => 'application/psd', 
					'icon' => 'data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAQAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABNAAAATQAAAE0AAABNAAAATQAAAE0AAABNAAAATQAAAE0AAABNAAAATQAAAE0AAABNAAAAAAAAAAAAAAAAJgAD/ykABP8tAAT/LwAE/zAABP8wAAT/MAAE/y8ABP8uAAP/LAAD/yoAA/8mAAP/IwAD/wAAAAAAAAAAAAAAACwABP8xAAT/NgAE/y0ABP86AAX/OgAF/zkABf8yAAT/LgAE/zEABP8yAAT/LQAD/ygAA/8AAAAAAAAAAAAAAAAxAAX/OAAF/z0ABv/6voL/PAAF/0AABv9BAAb/p2hJ/9+ibP+VWz7/OQAF/zMABP8tAAT/AAAAAAAAAAAAAAAANQAF/z4ABv9DAAb/+8KJ/5NUP/9TFxX/SQAH/1IXFf+OUTv/1phn/z8ABf85AAX/MAAE/wAAAAAAAAAAAAAAADkABf9CAAf/SQAH//3Gj/+PSjr/5a18/04ACP/NkWf/djot/zoABf9DAAb/PQAG/zQABP8AAAAAAAAAAAAAAAA7AAb/RAAH/0sAB//+yZT/QgAG//7JlP9RAAj/jUk5/+Spd/+4dlX/RgAG/z4ABv82AAX/AAAAAAAAAAAAAAAAPQAG/0gAB/9OAAj//smU/96kev+mZE7/VAAI/1AACP9LAAf/SQAH/0kAB/9BAAb/NwAF/wAAAAAAAAAAAAAAAD8ABv9KAAf/UQAI/04ACP9SAAj/UwAI/1gACf9WAAn/VQAJ/1AACP9KAAf/QgAH/zkABf8AAABNAAAATQAAAE0tAAP/NAAE/zoABf89AAb/QAAG/0AABv8+AAX/WQAJ/1cACf9SAAn/TAAH/0MABv85AAb//8CM///Ajf//wI3//8CN///Ajf//wI3//7+L//+/iv//von//72H/1sACf9YAAn/UwAJ/0wACP9EAAb/OAAF///CkP//w5H//8OS///Dkv//w5L//8KR///Bj///wY7//8CM//++iv9dAAr/WQAJ/1MACP9KAAj/QQAG/zcABf//w5L//8SV///Flv//xpf//8WV///Ek///w5H//8GP///Ajf//v4v/WwAK/1YACf/ktIX/4ax2/+OzhP95VkrD/8OS///Ek///xJX//8SV///Ek///w5L//8KQ///Bjv//wIz//7+K/1QACf9QAAn//MqY//zLmv+RaVvDAAAAAAAAAAAAAAAAAAAAADsABv9EAAf/SwAI/1AACP9SAAj/UgAI/08ACP9MAAj/RwAH//7Uq/+Sa17DAAAAAAAAAAAAAAAAAAAAAAAAAAA0AAX/OgAF/0AAB/9EAAf/RQAH/0UAB/9EAAf/QAAG/zwABv+Rb2bDAAAAAAAAAAAAAAAA4AAAAOAAAADgAAAA4AAAAOAAAADgAAAA4AAAAOAAAADgAAAAAAAAAAAAAAAAAAAAAAAAAAABAADgAwAA4AcAAA=='
				),
				array(
					'extension' => array(
						'dll',
						'mui'
					), 
					'datatype' => 'application/octet-stream', 
					'icon' => 'data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAQAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAenp6/2RkZP9kZGT/ZGRk/2RkZP9kZGT/ZGRk/2RkZP9kZGT/ZGRk/2RkZP9kZGT/cHBw/wAAAAAAAAAAAAAAAIWFhf/v7/H/8PDy//Dx8v/x8fP/8vLz//Lz9P/z9PX/9PT2//X19v/29vf/9vf4/4WFhf8AAAAAAAAAAAAAAACPj4//8PDy//Dx8v/x8fP/8vL0//Lz9P/z9PX/9PT2/+nl4//Qxr7/6ufl//f4+f+Pj4//AAAAAAAAAAAAAAAAnJyc//Hx8v/x8fP/8vL0//Pz9P/z9PX/9PT2/+fj4f++rZ7/i3Jc/7usn//4+fn/nJyc/wAAAAAAAAAAAAAAAKurq//x8fP/8vL0//Pz9P/z9PX/taWW/+vp6P/k3tf/i3Jc//7+/v+Lclz/7Orn/6urq/8AAAAAAAAAAAAAAACsrKz/8vL0//Pz9P/j4N3/u62j/5iBbv+8nYD/loBu/72tof+Lclz/xrOh/+3q6P+srKz/AAAAAAAAAAAAAAAAsLCw//Pz9f/s6ef/mIFu/+vGm/++noD/1KeC/56HdP+3lXj/29LJ/+rk3v/6+/v/sLCw/wAAAAAAAAAAAAAAALKysv/09PX/1Me4/86vjf/OsJP/6ubj/93UzP/QrIj/uqaS//b29P/6+/z/+/z8/7Kysv8AAAAAAAAAAAAAAAC0tLT/9fX2/5yFcv/Go4L/qpWF//j4+f/5+fr/ool1/56HdP/z8e7/+/z8//z9/f+0tLT/AAAAAAAAAAAAAAAAt7e3//X29//i1cf/7rB+/9K7pf+olYP/p5GA/9zHpf/GtaP/+vv7//z9/f/8/f3/t7e3/wAAAAAAAAAAAAAAALm5uf/29/j/8/Lx/6CJdv/eqHn/zZ95//fZuP+ginf/8u7q//v8/P/8/f3//P39/7e3t/8AAAAAAAAAAAAAAAC7u7v/9/j5//j5+f/29fT/7ujh/6CJd//z7OP/+Pf1//z9/f/8/f3/5OTl/97e3/+5ubn/AAAAAAAAAAAAAAAAvLy8//j5+f/5+vr/+vr7//r7+//7/Pz/+/z8//z9/f/8/f3/ubm5/7e3t/+3t7f/ubm5/wAAAAAAAAAAAAAAAL6+vv/5+vr/+vr7//r7+//7/Pz/+/z8//z9/f/8/f3//P39/8TExP/19fX/ubm5+d3d3V8AAAAAAAAAAAAAAAC/v7//+vr7//r7+//7/Pz/+/z8//z9/f/8/f3/+vv7//z9/f/Jycn/ubm5/ePl42kAAAAAAAAAAAAAAAAAAAAAv7+//7+/v/+/v7//v7+//7+/v/+/v7//v7+//7+/v/+/v7//vr6+/PX19XkAAAAAAAAAAAAAAAAAAAAAgAMAAIADAACAAwAAgAMAAIADAACAAwAAgAMAAIADAACAAwAAgAMAAIADAACAAwAAgAMAAIADAACABwAAgA8AAA=='
				),
				array(
					'extension' => array(
						'iso',
						'bin',
						'img'
					), 
					'datatype' => 'application/octet-stream', 
					'icon' => 'data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAQAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALD/8ACw//AAsP/wALD/8ACw//AAsP/wAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsP/wALD/+Pj4//n6e//5+nv/+/v8//v7/P/4+Pj/8ACw//AAsP/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAsP/19nb/+/v8//X3yv/z9Wj/8+R37/Tmuv/16Q3/9ukL//v7/P/25mbv8ACw//AAAAAAAAAAAAAAAAAAsP/25ubv+/x8//bo2//150r/9OXpD/Pkd+/05wsP9ekN//TnCw/z5LgP+fn6//bmZu/wALD/8AAAAAAAAAAAALD//P1+//fqnf/26cz/9fg7D/T2af/z5LgP9OcLD/XojP/z9Xj/8+R37/Tl6Q/7+/z/8ACw//AAAABQALD/+Pj4//j7ff/4/H7/9+qd//bpzP/36Qt/9fZn7/a3SQ/26Hv/8+S4D/TmCQ/15vn/9ukL//j4+P/wALD/8ACw//38/P/36Qt/9ugKD/b5fA/5+/3/+PiI//39ff/9/X3/+PiI//boCg/198r/9ujb//bpPA/7/Hz/8ACw//AAsP/+/n7///9/////f//9/X3/+Pj4//39ff/wAAAAAAAAAA39ff/36En/9+pdD/fqnf/36p3//P0N//AAsP/wALD//v5+///+fv///n7///39//n5+v/9/X3/8AAAAAAAAAAN/X3/9vd4//b5vA/36o0P9+qd//z9fv/wALD/8ACw//39ff///X3///z8///8fP//+/v/+QiI//39ff/9/X3/+Pj4///+fv/+/n7/+/v8//fpC3/7+/z/8ACw//AAsP/4+Pj///x8///7+///+vr///p6///5+f/5Bvb/+QfoD//7+////Pz///5+///+/v///3//+Pj4//AAsP/wAAAAAACw//79ff//+vr///n5///4+P//9+gP//b2///4+P//+nr///v7///8/P///f3//v5+//AAsP/wAAAAIAAAAAAAsP/25mbv//x8///5ef//9+gP//b2///3Z+//+Pj///n5///7e////Hz///39//b25v/wALD/8AAAAAAAAAAAAAAAAACw//bmZu///Hz///j4///25v//92fv//j4///5+f//+3v//v19//b25v/wALD/8AAAAAAAAAAAAAAAAAAAAAAAAAAAALD/8ACw//kIiP/9+/v///v7///8fP/9+/v/+Pj4//AAsP/wALD/8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALD/8ACw//AAsP/wALD/8ACw//AAsP/wAAAAAAAAAAAAAAAAAAAAAAAAAA+A8AAOAHAADAAwAAgAEAAIAAAAAAAAAAAAAAAAGAAAABgAAAAAAAAAAAAACAAAAAgAEAAMADAADgBwAA+B8AAA=='
				),
				array(
					'extension' => array(
						'lnk'
					), 
					'datatype' => 'application/octet-stream', 
					'icon' => !ALLOW_NONMOZILLA_ICONS ? 'data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAQAQAAAAAAAAAAAAAAAAAAAAAAAC1tbX/srKz/7Cwsf+tra7/q6us/6ioqf+mpaf/o6Ol/4iIhv+HhoX/hoWD/4SEgv+DgoD/goF+/wAAAAAAAAAAt7e4//f39//Xx7n/q4Jh//f39//39/f/9/f3/6alp//7+/r/+/v6//v7+v/7+/r/+/v6/4OCgP8AAAAAAAAAALq6uv/39/f/roVi/6JxSf/39/f/5dvS//f39/+oqKn/9/b1//f29f/39vX/9/b1//v7+v+EhIL/AAAAAAAAAAC8vL3/9/f3/8Kjif+aYTP/t5Fw/6BqP//39/f/q6us//f39v/39vX/9/b1//f29f/7+/r/hoWD/wAAAAAAAAAAv7+///f39//39/f/upJx/59kNf+fZDX/9/f3/62trv/49/b/+Pf2//f29f/39vX/+/v6/4eGhf8AAAAAAAAAAMHBwf/39/f/6NzU/6lwRP+kZzj/pGc4//f39/+wsLH/+Pf2//j39v/49/b/9/b2//v7+v+IiIb/AAAAAAAAAADExMT/9/f3//f39//39/f/9/f3//f39//39/f/srKz//j49//49/f/+Pf2//j39v/7+/v/iomI/wAAAAAAAAAAxsbG/8TExP/BwcH/v7+//7y8vf+6urr/t7e4/7W1tf/5+Pf/+fj3//j39//49/b//Pv7/4uKif8AAAAAAAAAAAAAAAAAAAAAm5ub//38/P/6+fj/+vn4//r5+P/5+fj/+fj4//n49//4+Pf/+Pf2//z7+/+NjIv/AAAAAAAAAAAAAAAAAAAAAJ2dnP/9/Pz/+vn5//r5+P/6+fj/+vn4//n5+P/5+Pf/+fj3//j49//8+/v/jo2M/wAAAAAAAAAAAAAAAAAAAACenp7//f38//r6+f/6+fn/+vn4//r5+P/6+fj/+fj4//n49//5+Pf//Pv7/4+Pjf8AAAAAAAAAAAAAAAAAAAAAoJ+f//39/f/6+vn/+vr5//r5+f/6+fj/+vn4//n5+P/5+Pj/+fj3//z7+/+RkI//AAAAAAAAAAAAAAAAAAAAAKGhof/9/f3/+/r6//r6+f/6+vn/+vn5//r5+P/5+fj/pqam/4yMjP+MjIz/kpKQ/wAAAAAAAAAAAAAAAAAAAACioqL//f39//v7+v/7+vr/+vr5//r5+f/6+fj/+vn4/6ampv/q6ur/1dXV/5iXlu8AAAAAAAAAAAAAAAAAAAAApKSj//39/f/9/f3//f39//39/P/9/Pz//fz8//38/P+mpqb/1tbW/5qame+Uj48wAAAAAAAAAAAAAAAAAAAAAKWlpf+kpKP/oqKi/6Ghof+gn5//np6e/52dnP+bm5v/mpqZ/5ycnO+UlJQwAAAAAAAAAAAAAAAAAAMAAAADAAAAAwAAAAMAAAADAAAAAwAAAAMAAAADAADAAwAAwAMAAMADAADAAwAAwAMAAMADAADAAwAAwAcAAA==' : 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABGdBTUEAANjr9RwUqgAAACBjSFJNAACHDwAAjA0AAPmTAACE5QAAe4IAAOt1AAA/tAAAIlh1a16cAAAD6GlDQ1BpY2MAAEjHjVXdb9tUFD+Jb1ykFj+gsY4OFYuvVVNbuRsarcYGSZOl6UIauc3YKqTJdW4aU9c2ttNtVZ/2Am8M+AOAsgcekHhCGgzE9rLtAbRJU0EV1SSkPXTaQGiT9oKqcK6vU7tdxriRr38553c+79E1QMdXmuOYSRlg3vJdNZ+Rj5+YljtWIQnPQSf0QKeme066XC4CLsaFR9bDXyHB3jcH2uv/c3VWqacDJJ5CbFc9fR7xaYCUqTuuDyDeRvnwKd9B3PE84h0uJohYYXiW4yzDMxwfDzhT6ihilouk17Uq4iXE/TMx+WwM8xyCtSNPLeoausx6UXbtmmHSWLpPUP/PNW82WvF68eny5iaP4ruP1V53x9QQf65ruUnELyO+5vgZJn8V8b3GXCWNeC9A8pmae6TC+ck3FutT7yDeibhq+IWpUL5ozZQmuG1yec4+qoaca7o3ij2DFxHfqtNCkecjQJVmc6xfiHvrjbHQvzDuLUzmWn4W66Ml7kdw39PGy4h7EH/o2uoEz1lYpmZe5f6FK45fDnMQ1i2zVOQ+iUS9oMZA7tenxrgtOeDjIXJbMl0zjhRC/pJjBrOIuZHzbkOthJwbmpvLcz/kPrUqoc/UrqqWZb0dRHwYjiU0oGDDDO46WLABMqiQhwy+HXBRUwMDTJRQ1FKUGImnYQ5l7XnlgMNxxJgNrNeZNUZpz+ER7oQcm3QThezH5yApkkNkmIyATN4kb5HDJIvSEXJw07Yci89i3dn08z400CvjHYPMuZ5GXxTvrHvS0K9/9PcWa/uRnGkrn3gHwMMOtJgD8fqvLv2wK/KxQi68e7Pr6hJMPKm/qdup9dQK7quptYiR+j21hr9VSGNuZpDRPD5GkIcXyyBew2V8fNBw/wN5doy3JWLNOtcTaVgn6AelhyU42x9Jld+UP5UV5QvlvHJ3W5fbdkn4VPhW+FH4Tvhe+Blk4ZJwWfhJuCJ8I1yMndXj52Pz7IN6W9UyTbteUzCljLRbeknKSi9Ir0jFyJ/ULQ1JY9Ie1OzePLd4vHgtBpzAvdXV9rE4r4JaA04FFXhBhy04s23+Q2vSS4ZIYdvUDrNZbjHEnJgV0yCLe8URcUgcZ7iVn7gHdSO457ZMnf6YCmiMFa9zIJg6NqvMeiHQeUB9etpnF+2o7Zxxjdm6L+9TlNflNH6qqFyw9MF+WTNNOVB5sks96i7Q6iCw7yC/oh+owfctsfN6JPPfBjj0F95ZNyLZdAPgaw+g+7VI1od34rOfAVw4oDfchfDOTyR+AfBq+/fxf10ZvJtuNZsP8L7q+ARg4+Nm85/lZnPjS/S/BnDJ/BdZAHF4zQTmIwAAAAlwSFlzAAAWJAAAFiQBmxXGFAAAABh0RVh0U29mdHdhcmUAcGFpbnQubmV0IDQuMC42/Ixj3wAAAR5JREFUOE9jGJSA8fnz5zrPnj0zQccPHjyQhKrBDc6ePat54sSJ/01NTRj46tWrZ4FKGCEqcQOmW7dutRUXF/9XVlZGwfv3778GlCdoAAgw37t3b7+pqel/eXl5ON67dy9xBty+fdu/rKzsn7S09H9kvHv3bsIGzJ8/n2PHjh0PxMXF/4uJif23trb+n5SUBGZv376dsAFA/0dHRkb+FxQU/O/m5vb/woULey5dutSfnp7+f+vmzYQNuHjhwkohIaH/dnZ2/y9evLirvr6eCyjMBDSo+dSpU3MgqnADJqAXboKce/To0WtAzQJQcRjAb3soMPT7+/ufFBQU/D9y8KAbVJgkwLhz584d0OhigQiRCIAJiBvodCEod9ADBgYAn4KegXL2g18AAAAASUVORK5CYII='
				),
				array(
					'extension' => array(
						'apk'
					), 
					'datatype' => 'application/apk', 
					'icon' => "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAAYdEVYdFNvZnR3YXJlAHBhaW50Lm5ldCA0LjAuNvyMY98AAAIYSURBVDhPhVNLaFNBFB0/decHBVFn0uCuRCyFgCh+CgUr2I0gVjfiSsWl4MJdwIXYjSiFQlXSTF7zii8JNX6CVmqQlmjMvF8+NjGNWAgUrPDAHyjW8U6cfhJf7YHDMO/ec+bMcB9qxp0JvH+Q+Vu0TOeO0XzPsbh1tOv2662b7qbJvkAKrZdtKyNstW9/UOh+9ezdqfnnlV6eLPfwYQt/D2VxJKD5Nsg2dwQ4WhvN+9OJYqc1Wjw4Fy92cNVu5WGdPInYhCsGDspWd1ADH1dtL4/Y3m8R2/NLiASHTfK5vlrk9xDb2Sbbl6BpaJ3G/JtDOr4McSv/I9V3nR4yvVsGGWqRcoReTJ+j49WzX/RaH536GHRys7ccVrvmpGeuOC/fn3fGKr1O4u1h537O51DWqopEikFiUo7Q2PRJ9rjcxVPVC8yavcHf1K7yyZlLfLx6hiemDvCR3O76VQSpjk2xhg1SknKEYoUOptoeniydYBMfLtaFD0tHGoSLBszFQDExEx/j+UMsWe7m0YLvH+ECXRMsGKhmG3M7dTldE4DrADzMJyiONAuaSRmJKSaZU3RCpfwvxPjCy950Ey0nDFO/VoCJ5GiNlC4hlPHsCRs4AUZfIRHExBmImoITOXAe9k9hVtpl+8qAZlucFsySvSIZTCAY4J+yvDoWDdINBj9keXVQnVyHu2bvTW7bKPZwjUfwQ0XrxQYg9AcNWp8r5Dff9wAAAABJRU5ErkJggg=="
				),
				array(
					'extension' => array(
						'jar'
					), 
					'datatype' => 'application/jar', 
					'icon' => 'data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAQAQAAAAAAAAAAAAAAAAAAAAAAABwWjpocFs8zHFbPP9xWzz/cVs8/3FbPP9xWzz/cVs8/3FbPP9xWzz/cVs8/3FbPP9xWzz/cVs8/3BbPMxwWjpodWBB4bWwqv/o6Oj/5+fn/+fn5//n5+f/5+fn/+fn5//n5+f/5+fn/+fn5//n5+f/5+fn/+rq6v+1sKr/dWBB4XtlR//f39//6Ojo/8e7q/+0oIf/po1t/6aNbf+mjW3/po1t/6aNbf+mjW3/po1t/+rq6v/s7Oz/39/f/3tlR/+Ba07/29vb/+fn5//f39//3Nzc/9nZ2f/Z2dn/2dnZ/9nZ2f/Z2dn/2dnZ/9nZ2f/l5eX/5+fn/9vb2/+Ba07/h3FV/9bW1v/k5OT/5OTk/+Dg4P+bhGb/k3hX/5N4WP+TeFf/m4Rm/+Dg4P+WfF3/rp2H/+Dg4P/U1NT/h3FV/454XP/Z2dn/5+fn/+Pj4//j4+P/ysK3/8nCtv/Jwrb/xr2w/8e9sP/d29j/2NjY/5d9Xv+vnon/1dXV/454XP+UgGP/3Nzc/+rq6v/m5ub/lHlY/5d8XP+dhmf/lXpa/5R5WP+dhmf/uqyb/+bm5v+UeVj/r56I/9jY2P+UgGP/m4dr/97e3v/t7e3/6enp/93d3f/d3d3/3t7e/yOC5P+AsOD/3t7e/+Pj4/+lkHX/rp6J/+Li4v/c3Nz/m4dr/6KNc//h4eH/8PDw//Dw8P/w8PD/7Ozs/zKK6f/h4eH/C3To/+zs7P/s7Oz/4+Pj/+bm5v/u7u7/4eHh/6KNc/+olHr/5OTk//Pz8//z8/P/8/Pz//Dw8P8Seen/8PDw/xJ56f8Seen/8PDw//Dw8P/z8/P/8/Pz/+Tk5P+olHr/r5uC/+fn5//29vb/9vb2//b29v/z8/P/lL3o/xl96f/n5+f/grTo/yWE6v/z8/P/9vb2//b29v/n5+f/r5uC/7Whif/p6en/+fn5//n5+f/5+fn/+fn5//Dw8P+JuOr/JYXr/+/v7/+60ev/9fX1//n5+f/5+fn/6enp/7Whif+6p5D/7Ozs//v7+//7+/v/+/v7//v7+//6+vr/8/Pz/4y77f83juz/9fX1//v7+//7+/v/+/v7/+zs7P+6p5D/v6yW/+3t7f/8/Pz//f39//39/f/9/f3//f39//z8/P/09PT/xNnw//r6+v/9/f3//f39//z8/P/t7e3/v6yW/8Owm8ze2tX/9fX1//f39//39/f/9/f3//f39//39/f/9/f3//T09P/39/f/9/f3//f39//19fX/3trV/8Owm8zGsp9oyLWezMi1n//ItZ//yLWf/8i1n//ItZ//yLWf/8i1n//ItZ//yLWf/8i1n//ItZ//yLWf/8i1nszGsp9oAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=='
				),
				array(
					'extension' => array(
						'db'
					), 
					'datatype' => 'application/octet-stream', 
					'icon' => 'data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAQAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJGQj/+Pj43/jo2M/42Mi/+Lion/iomI/4iIhv+HhoX/hoWD/4SEgv+DgoD/goF+/wAAAAAAAAAAAAAAAAAAAACSkpD/+/v6//v7+v/7+/r/+/v6//v7+v/7+/r/+/v6//v7+v/7+/r/+/v6/4OCgP8AAAAAAAAAAAAAAAAAAAAAk5OS//z7+//49/b/+Pf2//f29v/39vX/9/b1//f29f/39vX/9/b1//v7+v+EhIL/AAAAAAAAAAAAAAAAAAAAAJWUk//8+/v/+Pf2//j39v/49/b/+Pf2/+/u7v++urT/ta2i/9bSy//z8/L/hoWD/wAAAAAAAAAAAAAAAAAAAACWlpX//Pz7//j39//49/f/+Pf2//j39v/Gwrz/6M6j//v06P/mzaD/4N3W/4eGhf8AAAAAAAAAAAAAAAAAAAAAl5eW//z8+//5+Pf/+fj3/8LBwf+Lior/mpOH//v06f/u06T/+vTo/7Wuov+IiIb/AAAAAAAAAAAAAAAAAAAAAJmYmP/8/Pz/+fj4/52dm//c2tX/5eLb/9HLwP/ozqL/+/To/+XMn//HxL3/iomI/wAAAAAAAAAAAAAAAAAAAACampn//fz8/8vLyv/c2tb/+vr5/6ampv/z8/H/ycO2/5mShv++urP/9PPz/4uKif8AAAAAAAAAAAAAAAAAAAAAm5ub//38/P+Li4v/5ePf/6ampv//////pqam/+fi1v+Lior/+Pf2//z7+/+NjIv/AAAAAAAAAAAAAAAAAAAAAJ2dnP/9/Pz/zMvL/9za1P/6+vj/pqam//r59v/a1cf/y8rK//j49//8+/v/jo2M/wAAAAAAAAAAAAAAAAAAAACenp7//f38//r6+f+dnJr/29jQ/+Tg1f/a1sn/k5KO//n49//5+Pf//Pv7/4+Pjf8AAAAAAAAAAAAAAAAAAAAAoJ+f//39/f/6+vn/+vr5/8PCwv+Li4v/wsLB//n5+P/5+Pj/+fj3//z7+/+RkI//AAAAAAAAAAAAAAAAAAAAAKGhof/9/f3/+/r6//r6+f/6+vn/+vn5//r5+P/5+fj/pqam/4yMjP+MjIz/kpKQ/wAAAAAAAAAAAAAAAAAAAACioqL//f39//v7+v/7+vr/+vr5//r5+f/6+fj/+vn4/6ampv/q6ur/1dXV/5iXlu8AAAAAAAAAAAAAAAAAAAAApKSj//39/f/9/f3//f39//39/P/9/Pz//fz8//38/P+mpqb/1tbW/5qame+Uj48wAAAAAAAAAAAAAAAAAAAAAKWlpf+kpKP/oqKi/6Ghof+gn5//np6e/52dnP+bm5v/mpqZ/5ycnO+UlJQwAAAAAAAAAAAAAAAAwAMAAMADAADAAwAAwAMAAMADAADAAwAAwAMAAMADAADAAwAAwAMAAMADAADAAwAAwAMAAMADAADAAwAAwAcAAA=='
				)
			);
	}
	
	if ($_POST['logout'] == 'true') unauthorize();
	
	if(!checkAuth(true)) {
		if(authorize() == null) {
			echo '
<!DOCTYPE html>
<html dir="ltr" lang="ru">
	<head>
		<meta charset="utf-8">
		<title>FileManager Server: Authorisation</title>
	</head>
	<body style="font-size: 82%; font-family: sans-serif; padding: 0; margin: 0; color: #444; background: #fff;">
		<div style="margin: 0; text-align: center;">
			<div style="margin: 0 .5em;">
				<div style="text-align: left; width: 30em; margin: 0 auto;">
					<form method="post" autocomplete="off" style="display: inline;" style="padding: 0; margin: 0;">
						<fieldset style="margin-top: 1em; border-radius: 4px 4px 0 0; -moz-border-radius: 4px 4px 0 0; -webkit-border-radius: 4px 4px 0 0; border: #aaa solid 1px; padding: 1.5em; background: #eee; text-shadow: 1px 1px 2px #fff inset; -moz-box-shadow: 1px 1px 2px #fff inset; -webkit-box-shadow: 1px 1px 2px #fff inset; box-shadow: 1px 1px 2px #fff inset;">
							<legend style="font-weight: bold; color: #444; padding: 5px 10px; border-radius: 2px; -moz-border-radius: 2px; -webkit-border-radius: 2px; border: 1px solid #aaa; background-color: #fff; -moz-box-shadow: 3px 3px 15px #bbb; -webkit-box-shadow: 3px 3px 15px #bbb; box-shadow: 3px 3px 15px #bbb; max-width: 100%;">Авторизация</legend>
							<div>
								<label for="user" style="float: left; width: 10em; font-weight: bolder;">Пользователь:</label>
								<input name="user" id="user" size="24" type="text" style="margin: 6px; border-radius: 2px; -moz-border-radius: 2px; -webkit-border-radius: 2px; background: white; border: 1px solid #aaa; color: #555; padding: 4px; border: 1px solid #7c7c7c; background: #fff;box-sizing: border-box; width: 14em;">
							</div>
							<div>
								<label for="pass" style="float: left; width: 10em; font-weight: bolder;">Пароль:</label>
								<input name="pass" id="pass" value="" size="24" type="password" style="margin: 6px; border-radius: 2px; -moz-border-radius: 2px; -webkit-border-radius: 2px; background: white; border: 1px solid #aaa; color: #555; padding: 4px; border: 1px solid #7c7c7c; background: #fff;box-sizing: border-box; width: 14em;">
							</div>
						</fieldset>
						<fieldset  style="margin-top: 1em; border-radius: 4px 4px 0 0; -moz-border-radius: 4px 4px 0 0; -webkit-border-radius: 4px 4px 0 0; border: #aaa solid 1px; padding: 1.5em; background: #eee; text-shadow: 1px 1px 2px #fff inset; -moz-box-shadow: 1px 1px 2px #fff inset; -webkit-box-shadow: 1px 1px 2px #fff inset; box-shadow: 1px 1px 2px #fff inset; font-weight: normal; color: #000; background: #D3DCE3; margin-top: 0; margin-bottom: .5em; border-top: 0; text-align: right; float: none; clear: both; -webkit-border-radius: 0 0 4px 4px; -moz-border-radius: 0 0 4px 4px; border-radius: 0 0 4px 5px;">
							<input value="Вперёд"  style="margin: 6px 14px; border: 1px solid #aaa; padding: 3px 7px; color: #111; text-decoration: none; background: #ddd; border-radius: 12px; -webkit-border-radius: 12px; -moz-border-radius: 12px; text-shadow: 0 1px 0 #fff; background-size: 100% 100%; background: -webkit-gradient(linear, left top, left bottom, from(#f8f8f8), to(#d8d8d8)); background: -webkit-linear-gradient(top, #f8f8f8, #d8d8d8); background: -moz-linear-gradient(top, #f8f8f8, #d8d8d8); background: -ms-linear-gradient(top, #f8f8f8, #d8d8d8); background: -o-linear-gradient(top, #f8f8f8, #d8d8d8); border: 1px solid #7c7c7c; background: #fff;box-sizing: border-box; width: 14em;" type="submit">
						</fieldset>
					</form>
				</div>
			</div>
		</div>
	</body>
</html>
			';
		} else {
			header('Location: '.$_SERVER['SCRIPT_NAME']);
		}
		exit;
	}
	
	if (!isset($_GET['filename'])) {

		$folder_name = str_replace ('\\', '/', $_GET['folder'] ? $_GET['folder'] : "./");
		$dir = glob($folder_name . "*");
		$up = explode ('/', $folder_name);
		for ($i = 0; $i < count($up) - 2; $i++) {
			$d .= $up[$i] . '/';
		}
		function abc_dir ($array, $direction = true) {
			foreach ($array as $value) {
				if (is_dir($value)) {
					$dir_array[count($dir_array)] = $value;
				} else {
					if (!validate2AuthFile($value, true))
						$file_array[count($file_array)] = $value;
				}
			}
			if ($direction) {
				asort($dir_array);
				asort($file_array);
			} else {
				arsort($dir_array);
				arsort($file_array);
			}
			$_1 = $direction ? $dir_array : $file_array;
			$_2 = $direction ? $file_array : $dir_array;
			
			$c = $direction ? count($dir_array) : count($file_array);
			$toI = $direction ? count($file_array) : count($dir_array);
			if ($direction) {
				for ($i = 0; $i < $toI; $i++) {
					$_1[$c + $i + 1] = $_2[$i];
				}
			} else {
				for ($i = $toI - 1; $i >= 0; $i--) {
					$_1[$c + $i + 1] = $_2[$i];
				}
			}
			return $_1;
		}
		$dir = abc_dir ($dir, !isset($_GET['name_reverse']));
		
		function get_args ($ignore_path = true, $ignore_reverse = false) {
			foreach ($_GET as $key => $value) {
				if (trim($key) == 'folder' && $ignore_path)
					continue;
				if (trim($key) == 'name_reverse' && $ignore_reverse)
					continue;
				$string .= '&' . trim($key) . (trim($value) == null ? null : '=' . trim($value));
			}
			return $string;
		}
		
		function icon_reciver($filename, $file_types) {
			if (!is_dir($filename)) {
				$pi = pathinfo($filename);
				$extension = strtolower($pi['extension']);
				
				foreach ($file_types as $value) {
					foreach ($value['extension'] as $ext) {
						if ($ext == $extension) {
							$ico = $value['icon'];
							break 2;
						}
					}
				}
				if ($ico == null) $ico = 'data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAQAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOXg2u/DwLv/wr65/8C8uP++u7b/vbm1/7y4tP+7t7L/urax/7m1sf+4tbD/uLSw/7ezr//X0s3vAAAAAAAAAADFwbz/Wlpa/1NTU/9NTU3/R0dH/0FBQf88PDz/ODg4/zQ0NP8xMTH/KWIp/ywsLP8rKyv/pKCc/wAAAAAAAAAAxcG8/1paWv9TU1P/TU1N/0dHR/9BQUH/PDw8/zg4OP80NDT/M2Qz/1v/W/8hYSH/Kysr/6SgnP8AAAAAAAAAAMXBvP9aWlr/U1NT/01NTf9HR0f/QUFB/zw8PP84ODj/NDQ0/zExMf8mYib/LCws/ysrK/+koJz/AAAAAAAAAADY087vsKyp/66qp/+sqaX/q6ej/6mmov+opaH/p6Og/6ain/+lop7/paGd/6Shnf+koJ3/y8bC7wAAAAAAAAAA4+HfcOTh3//i393/4d3b/9/c2f/d2tf/3NjV/9rW1P/Y1NL/19LQ/9XRzv/Tz8z/0s3K/8/Jx2AAAAAAAAAAAAAAAADi4N2/5tam/+nNbf/pzGz/3drX/9zY1f/a1tT/2NTS/9fS0P/V0c7/08/M/9HMyb8AAAAAAAAAAPG7AN/yvAD/39/XIPK8AP/yvAD/8rwA/93a1//c2NX/2tbU/9jU0v/X0tD/1dHO/9PPzP/Px8cgAAAAAAAAAADyvAD/8rwA/wAAAADyvAD/8rwA//K8AP8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPK8AP/yvAD/AAAAAPK8AP/yvAD/8rwA/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADxuwDf8rwA/wAAAADyvAD/8rwA//K8AP8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA77sAQPG7AIDxuwCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA//8AAIABAACAAQAAgAEAAIABAACAAQAAgAEAAMADAAAAAwAAI/8AAP//AAAj/wAAI/8AAOP/AAD//wAA//8AAA==';
			} else {
				$ico = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAd5JREFUeNqMU79rFUEQ/vbuodFEEkzAImBpkUabFP4ldpaJhZXYm/RiZWsv/hkWFglBUyTIgyAIIfgIRjHv3r39MePM7N3LcbxAFvZ2b2bn22/mm3XMjF+HL3YW7q28YSIw8mBKoBihhhgCsoORot9d3/ywg3YowMXwNde/PzGnk2vn6PitrT+/PGeNaecg4+qNY3D43vy16A5wDDd4Aqg/ngmrjl/GoN0U5V1QquHQG3q+TPDVhVwyBffcmQGJmSVfyZk7R3SngI4JKfwDJ2+05zIg8gbiereTZRHhJ5KCMOwDFLjhoBTn2g0ghagfKeIYJDPFyibJVBtTREwq60SpYvh5++PpwatHsxSm9QRLSQpEVSd7/TYJUb49TX7gztpjjEffnoVw66+Ytovs14Yp7HaKmUXeX9rKUoMoLNW3srqI5fWn8JejrVkK0QcrkFLOgS39yoKUQe292WJ1guUHG8K2o8K00oO1BTvXoW4yasclUTgZYJY9aFNfAThX5CZRmczAV52oAPoupHhWRIUUAOoyUIlYVaAa/VbLbyiZUiyFbjQFNwiZQSGl4IDy9sO5Wrty0QLKhdZPxmgGcDo8ejn+c/6eiK9poz15Kw7Dr/vN/z6W7q++091/AQYA5mZ8GYJ9K0AAAAAASUVORK5CYII=';
			}
			return $ico;
		}
		
		function size ($file) {
			if (is_dir($file)) {
				return null; 
			} else {
				clearstatcache();
				$size_broken = filesize($file);
				$handle = fopen($file, 'r');
				fseek($handle, 0, SEEK_END);  
				$size = sprintf("%u", ftell($handle));  
				fclose($handle);
				
				$overflow = 'Overflow';
				
				if ($size_broken != $size && $size == 0) {
					$size = $overflow;
				}
				
				if ($size >= 1024 && $size < 1024*1024) {
					return round($size / 1024) . ' KB';
				} elseif ($size >= 1024*1024 && $size < 1024*1024*1024) {
					return round(($size / 1024) / 1024) . ' MB';
				} elseif ($size >= 1024*1024*1024 && $size < 1024*1024*1024*1024) {
					return round((($size / 1024) / 1024) / 1024, 2) . ' GB';
				} else {
					return $size . ($size == $overflow ? null : ' B');
				}
			}
		}
	} else {
		$file = $_GET['filename'] ? $_GET['filename'] : 'index.php';
		
		if (!validate2AuthFile($file, true)) {
			$pi = pathinfo($file);
			$extension = strtolower($pi['extension']);
			
			foreach ($file_types as $value) {
				foreach ($value['extension'] as $ext) {
					if ($ext == $extension) {
						$ctype = $value['datatype'];
						break 2;
					}
				}
			}
			if ($ctype == null) $ctype = "application/" . $extension;
			header('Content-Disposition: inline; filename="' . basename($file) . '";');
			header('Content-Transfer-Encoding: binary');
			header('Expires: 0');
			header('Cache-Control: must-revalidate');
			header('Pragma: public');
			
			header("Content-type:" . $ctype);
			if ($extension == 'php' or $extension == 'xml' or $extension == 'txt' or $extension == 'lcf') {
				echo str_replace(PHP_EOL, '<br />', str_replace('<', '&#60;', file_get_contents($file)));
			} else {
				readfile($file);
			}
			exit;
		} else {
			header('Location: '.$_SERVER['SCRIPT_NAME']);
		}
	}
?>

<!DOCTYPE html>
<html>
	<head>
		<meta http-equiv="content-type" content="text/html" charset="UTF-8">
		<style>
			/* This Source Code Form is subject to the terms of the Mozilla Public
			* License, v. 2.0. If a copy of the MPL was not distributed with this
			* file, You can obtain one at http://mozilla.org/MPL/2.0/. */
			
			.logout {
				position: fixed;
				width: 64px;
				height: 64px;
				top: 0px;
				right: 0px;
				margin: 0; 
				padding: 0;
				background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAIAAAAlC+aJAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAAZdEVYdFNvZnR3YXJlAHBhaW50Lm5ldCA0LjAuMjCGJ1kDAAAB/UlEQVRoQ+2X226CQBCG+yzlvlqoHLr1WTTxETWgF5IoF8JT6Iuo/SPNlk6QCLt2IJnkC+Ewm8w3zC7Ly6vjDBoR4EYEuBEBbkSAGxHgRgS4EQFuRIAbEeBGBLixIDCbzZbLpet65H4DCMaQ+XxO7nfAVABJHI/Hy+WSJEkYRuRpLQhDMIZgoLmDqQAKiVSu1yuO2+32bTQiAQQEIEwPwXAS0BZTATRDWU4kdD6f9/u97wckRjOZ+LvdDmFl9hjYqvFqsTAH0BIoqk4rjuNaB2SPR1oVQx5suWYsCAA0BmpfJocjzkkv4RK1bwjojB0BgKrfK/CDr6gb1gQA0kJpSYu3miQdsCkAyCKT5/nhcNCXeGSrczSWBUCkvjabjU5an+DmdDolwebYFwBBEBR5XqZeZl8UBVYhEmaFZwmgdaoCuDRf8mv5vxbCVLay8BOeMYlTnfRtEv/0Eo59n8S1y6g38fULwaMsy5T6JANNsCagorD6IUsrHzIsPmmaVsWCvn3IPO8jy363EiizO/7TKu77GC9HB/RrKxFGqlrgOEmUUiQGNOw1TDAVuO0U1jotlDaI7rZ47SQhMW0xFVitVmX2OD6yyNyWqT790CwWi9PphFTW62H+UgIkMeCfenZEgBsR4EYEuBEBbkSAGxHgRgS4EQFuRIAbEeDFcb4BIAI0E2WYJUMAAAAASUVORK5CYII=);
			}
			
			.logout:hover {
				background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAIAAAAlC+aJAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAAZdEVYdFNvZnR3YXJlAHBhaW50Lm5ldCA0LjAuMjCGJ1kDAAAB/UlEQVRoQ+2XbW6CQBCGe45yh2qh8tGtZ9HEI2pAf0ii/BBOoRdR+0aaLZ0gEXbtQDLJE8LHbDLPMLssL6+OM2hEgBsR4EYEuBEBbkSAGxHgRgS4EQFuRIAbEeDGgsBsNlsul67rkfsNIBhD5vM5ud8BUwEkcTweL5dLkiRhGJGntSAMwRiCgeYOpgIoJFK5Xq84brfbt9GIBBAQgDA9BMNJQFtMBdAMZTmR0Pl83u/3vh+QGM1k4u92O4SV2WNgq8arxcIcQEugqDqtOI5rHZA9HmlVDHmw5ZqxIADQGKh9mRyOOCe9hEvUviGgM3YEAKp+r8APvqJuWBMASAulJS3eapJ0wKYAIItMnueHw0Ff4pGtztFYFgCR+tpsNjppfYKb0+mUBJtjXwAEQVDkeZl6mX1RFFiFSJgVniWA1qkK4NJ8ya/l/1oIU9nKwk94xiROddK3SfzTSzj2fRLXLqPexNcvBI+yLFPqkww0wZqAisLqhyytfMiw+KRpWhUL+vYh87yPLPvdSqDM7vhPq7jvY7wcHdCvrUQYqWqB4yRRSpEY0LDXMMFU4LZTWOu0UNogutvitZOExLTFVGC1WpXZ4/jIInNbpvr0Q7NYLE6nE1JZr4f5SwmQxIB/6tkRAW5EgBsR4EYEuBEBbkSAGxHgRgS4EQFuRIAXx/kGIwHL9VqEb5oAAAAASUVORK5CYII=);
			}
			
			:root {
				background-color: -moz-dialog;
				color: -moz-dialogtext;
				font: message-box;
				padding-left: 2em;
				padding-right: 2em;
			}
			
			body {
				border: 1px solid ThreeDShadow;
				border-radius: 10px;
				padding: 3em;
				min-width: 30em;
				max-width: 65em;
				margin: 4em auto;
				background-color: -moz-field;
				color: -moz-fieldtext;
			}
			
			h1 {
				font-size: 160%;
				margin: .6em;
				border-bottom: 1px solid ThreeDLightShadow;
				font-weight: normal;
				border-bottom-color: #E3E3E3;
				border-bottom-style: solid;
				border-bottom-width: 1px;
				color: #000;
				font-family: Segoe UI;
				font-feature-settings: normal;
				font-kerning: auto;
				font-language-override: normal;
				font-size: 19.2px;
				font-size-adjust: none;
				font-stretch: normal;
				font-style: normal;
				font-synthesis: weight style;
				font-variant: normal;
				font-variant-alternates: normal;
				font-variant-caps: normal;
				font-variant-east-asian: normal;
				font-variant-ligatures: normal;
				font-variant-numeric: normal;
				font-variant-position: normal;
				font-weight: 400;
				line-height: 26px;
				margin-bottom: 11.5167px;
				margin-left: 0px;
				margin-right: 0px;
				margin-top: 0px;

			}
			
			a {
				text-decoration: none;
			}
			
			a:hover {
				text-decoration: underline;
			}
			
			p {
				font-size: 110%;
			}
			
			#UI_goUp {
				margin-top: 0;
				float: left;
			}
			
			#UI_goUp:-moz-dir(rtl) {
				float: right;
			}
			
			#UI_showHidden {
				margin-top: 0;
				float: right;
			}
			
			#UI_showHidden:-moz-dir(rtl) {
				float: left;
			}
			
			table {
				clear: both;
				width: 90%;
				margin: 0 auto;
			}
			
			thead {
				font-size: 130%;
			}
			
			/* last modified */
			th:last-child {
				text-align: center;
			}
			
			th:hover > a {
				text-decoration: underline;
			}
			
			tbody > tr:hover {
				outline: 1px solid ThreeDLightShadow;
				-moz-outline-radius: .3em;
			}
			
			/* let 'Size' and 'Last Modified' take only as much space as they need and 'Name' all the rest */
			td:not(:first-child) {
				width: 0;
			}
			root {
				font-family: sans-serif;
			}
			img {
				border: 0;
			}
			th {
				text-align: start;
				white-space: nowrap;
			}
			th > a {
				color: inherit;
			}
			table[order] > thead > tr > th {
				cursor: pointer;
			}
			table[order] > thead > tr > th::after {
				display: none;
				width: .8em;
				-moz-margin-end: -.8em;
				text-align: end;
			}
			table[order="asc"] > thead > tr > th::after {
				content: "\2193"; /* DOWNWARDS ARROW (U+2193) */
			}
			table[order="desc"] > thead > tr > th::after {
				content: "\2191"; /* UPWARDS ARROW (U+2191) */
			}
			table[order][order-by="0"] > thead > tr > th:first-child > a ,
			table[order][order-by="1"] > thead > tr > th:first-child + th > a ,
			table[order][order-by="2"] > thead > tr > th:first-child + th + th > a {
				text-decoration: underline;
			}
			table[order][order-by="0"] > thead > tr > th:first-child::after ,
			table[order][order-by="1"] > thead > tr > th:first-child + th::after ,
			table[order][order-by="2"] > thead > tr > th:first-child + th + th::after {
				display: inline-block;
			}
			table.remove-hidden > tbody > tr.hidden-object {
				display: none;
			}
			td {
				white-space: nowrap;
			}
			table.ellipsis {
				width: 100%;
				table-layout: fixed;
				border-spacing: 0;
			}
			table.ellipsis > tbody > tr > td {
				padding: 0;
				overflow: hidden;
				text-overflow: ellipsis;
			}
			/* name */
			/* name */
			th:first-child {
				-moz-padding-end: 2em;
			}
			/* size */
			th:first-child + th {
				-moz-padding-end: 1em;
			}
			td:first-child + td {
				text-align: end;
				-moz-padding-end: 1em;
			}
			/* date */
			td:first-child + td + td {
				-moz-padding-start: 1em;
				-moz-padding-end: .5em;
			}
			/* time */
			td:first-child + td + td + td {
				-moz-padding-start: .5em;
			}
			.symlink {
				font-style: italic;
			}
			.dir ,
			.symlink ,
			.file {
				-moz-margin-start: 20px;
			}
			.dir::before ,
			.file > img {
				-moz-margin-end: 4px;
				-moz-margin-start: -20px;
				max-width: 16px;
				max-height: 16px;
				vertical-align: middle;
			}
			html {
				background-color:#F0F0F0;
			}
			body {
				background-color:#FFF;
				border-bottom-color:#A0A0A0;
				border-bottom-left-radius:10px;
				border-bottom-right-radius:10px;
				border-bottom-style:solid;
				border-bottom-width:1px;
				border-image-outset:0 0 0 0;
				border-image-repeat:stretch stretch;
				border-image-slice:100% 100% 100% 100%;
				border-image-source:none;
				border-image-width:1 1 1 1;
				border-left-color:#A0A0A0;
				border-left-style:solid;
				border-left-width:1px;
				border-right-color:#A0A0A0;
				border-right-style:solid;
				border-right-width:1px;
				border-top-color:#A0A0A0;
				border-top-left-radius:10px;
				border-top-right-radius:10px;
				border-top-style:solid;
				border-top-width:1px;
				color:#000;
				font-family:Segoe UI;
				font-feature-settings:normal;
				font-kerning:auto;
				font-language-override:normal;
				font-size:12px;
				font-size-adjust:none;
				font-stretch:normal;
				font-style:normal;
				font-synthesis:weight style;
				font-variant:normal;
				font-variant-alternates:normal;
				font-variant-caps:normal;
				font-variant-east-asian:normal;
				font-variant-ligatures:normal;
				font-variant-numeric:normal;
				font-variant-position:normal;
				font-weight:400;
				line-height:17px;
				
				max-width:780px;
				min-width:360px;
				padding-bottom:36px;
				padding-left:36px;
				padding-right:36px;
				padding-top:36px;
			}
		</style>
		<link rel="icon" type="image/png" href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAjFJREFUeNqsU8uOElEQPffR3XQ3ONASdBJCSBxHos5+3Bg3rvkCv8PElS78gPkO/ATjQoUdO2ftrJiRh6aneTb9sOpC4weMN6lcuFV16pxDIfI8x12OYIDhcPiu2Wx+/HF5CW1Z6Jyegt/TNEWSJIjjGFEUIQxDrFYrWFSzXC4/dLvd95pRKpXKy+pRFZ7nwaWo1+sGnQG2260BKJfLKJVKGI1GEEJw7ateryd0v993W63WEwjgxfn5obGYzgCbzcaEbdsIggDj8Riu6z6iUk9SYZMSx8W0LMsM/SKK75xnJlIq80anQXdbEp0OhcPJ0eiaJnGRMEyyPDsAKKUM9clkYoDo3SZJzzSdp0VSKYmfV1co+z580kw5KDIM8RbRfEnUf1HzxtQyMAGcaGruTKczMzEIaqhKifV6jd+zGQQB5llunF/M52BizC2K5sYPYvZcu653tjOM9O93wnYc08gmkgg4VAxixfqFUJT36AYBZGd6PJkFCZnnlBxMp38gqIgLpZB0y4Nph18lyWh5FFbrOSxbl3V4G+VB7T4ajYYxTyuLtO+CvWGgJE1Mc7JNsJEhvgw/QV4fo/24nbEsX2u1d5sVyn8sJO0ZAQiIYnFh+xrfLz/j29cBS/O14zg3i8XigW3ZkErDtmKoeM+AJGRMnXeEPGKf0nCD1ydvkDzU9Jbc6OpR7WIw6L8lQ+4pQ1/lPF0RGM9Ns91Wmptk0GfB4EJkt77vXYj/8m+8y/krwABHbz2H9V68DQAAAABJRU5ErkJggg==">
		<title>Содержимое «<?php echo $folder_name;?>»</title>
	</head>
	<body dir="ltr">
		<form method="post" class="logout">
			<input type="hidden" name="logout" value="true"> 
			<input value="" type="submit" style="margin: 0; padding: 0; height: 64px; width: 64px; background: none; cursor: pointer; border: none;">
		</form>
		<h1>Содержимое «<?php echo $folder_name;?>»</h1>
		<p>
			<a style="text-decoration: none; color:#0000EE" href="<?php echo 'http://' . $_SERVER['HTTP_HOST'] . $_SERVER['SCRIPT_NAME'] . '?folder=' . $d . get_args();?>">
				<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAmlJREFUeNpsU0toU0EUPfPysx/tTxuDH9SCWhUDooIbd7oRUUTMouqi2iIoCO6lceHWhegy4EJFinWjrlQUpVm0IIoFpVDEIthm0dpikpf3ZuZ6Z94nrXhhMjM3c8895977BBHB2PznK8WPtDgyWH5q77cPH8PpdXuhpQT4ifR9u5sfJb1bmw6VivahATDrxcRZ2njfoaMv+2j7mLDn93MPiNRMvGbL18L9IpF8h9/TN+EYkMffSiOXJ5+hkD+PdqcLpICWHOHc2CC+LEyA/K+cKQMnlQHJX8wqYG3MAJy88Wa4OLDvEqAEOpJd0LxHIMdHBziowSwVlF8D6QaicK01krw/JynwcKoEwZczewroTvZirlKJs5CqQ5CG8pb57FnJUA0LYCXMX5fibd+p8LWDDemcPZbzQyjvH+Ki1TlIciElA7ghwLKV4kRZstt2sANWRjYTAGzuP2hXZFpJ/GsxgGJ0ox1aoFWsDXyyxqCs26+ydmagFN/rRjymJ1898bzGzmQE0HCZpmk5A0RFIv8Pn0WYPsiu6t/Rsj6PauVTwffTSzGAGZhUG2F06hEc9ibS7OPMNp6ErYFlKavo7MkhmTqCxZ/jwzGA9Hx82H2BZSw1NTN9Gx8ycHkajU/7M+jInsDC7DiaEmo1bNl1AMr9ASFgqVu9MCTIzoGUimXVAnnaN0PdBBDCCYbEtMk6wkpQwIG0sn0PQIUF4GsTwLSIFKNqF6DVrQq+IWVrQDxAYQC/1SsYOI4pOxKZrfifiUSbDUisif7XlpGIPufXd/uvdvZm760M0no1FZcnrzUdjw7au3vu/BVgAFLXeuTxhTXVAAAAAElFTkSuQmCC" alt="Up">&nbsp;&nbsp;
				Перейти в каталог на уровень выше
			</a>
		</p>
		<table order="">
			<thead>
				<tr>
					<th style="text-align:left;">
						<a style="text-decoration: none;" href="<?php echo 'http://' . $_SERVER['HTTP_HOST'] . $_SERVER['SCRIPT_NAME'] . (isset ($_GET['name_reverse']) ? '?' : '?name_reverse') . get_args(false, true); ?>">
							Имя&nbsp;<?php echo isset($_GET['name_reverse']) ? '&#8593;' : '&#8595;' ?>&nbsp;&nbsp;&nbsp;
						</a>
					</th>
					<th style="text-align:right;">
						<a style="text-decoration: none;" href="">
							Тип&nbsp;&nbsp;&nbsp;&nbsp;
						</a>
					</th>
					<th style="text-align:right;">
						<a style="text-decoration: none;" href="">
							Размер&nbsp;&nbsp;&nbsp;&nbsp;
						</a>
					</th>
					<th colspan="2" style="text-align:right;">
						<a style="text-decoration: none;" href="">
							Последнее изменение
						</a>
					</th>
				</tr>
			</thead>
			<tbody>
				<?php 
					foreach ($dir as $value) {
						$ext = pathinfo($value);
						$name = explode($folder_name, $value);
						$boarder = 55;
						if (strlen($name[count($name) - 1]) > $boarder) {
							for ($i = 0; $i < $boarder - 3; $i++) {
								$n1 .= $name[count($name) - 1][$i];
							}
							$name[count($name) - 1] = $n1 . '...';
						}
						echo 
							'<tr>
								<td>
									<a class="file" href="' . 'http://' . $_SERVER['HTTP_HOST'] . $_SERVER['SCRIPT_NAME'] . (is_dir($value) ? ('?folder=' . urlencode($value) . '/' . get_args()) : ('?filename=' . urlencode($value))) . '" style="text-decoration: none; color:#0000EE">
										<img src="' . icon_reciver($value, $file_types) . '" alt="PC" style="margin-right: 4px; max-width: 16px; min-width: 16px; max-height: 16px; min-height: 16px;">' . $name[count($name) - 1] . '
									</a>
								</td>
								<td style="text-align: right;">
									' . strtoupper(is_dir($value) ? 'Folder' : ($ext['extension'] ? $ext['extension'] : 'File')) . '
								</td>
								<td style="text-align: right;">' . 
									size($value) . '
								</td>
								<td style="text-align: right;">' . 
									date( 'd.m.Y', filemtime($value)) . '
								</td>
								<td style="text-align: right;">' . 
									date( 'H:i:s', filemtime($value)) . '
								</td>
							</tr>
							<tr>
							</tr>';
						unset($n1);
					}
				?>
			</tbody>
		</table>
	</body>
</html>