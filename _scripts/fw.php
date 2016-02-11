#! /usr/bin/php
<?

class FwCfg {

	// filesystem stuff
	var $filename; // main config: fw.cfg
	var $line;
	var $cwd; // path to includes
	var $template; // internal: template for iptables-restore

	var $default_fw_rule = 'DROP';

	var $nets = array();
	var $extras = array(
		'fw' => array(),
		'nat' => array()
	);

	function net_to_chain($prefix, $net)
	{
		return substr($prefix.'_'.($this->nets[$net]['index']).'_'.$net, 0, 30);
	}

	function nets_to_chain($prefix, $net1, $net2)
	{
		assert(strlen($prefix) + strlen($this->nets[$net1]['index']) + strlen($this->nets[$net1]['index']) + 2 < 30);

		$net1 = $this->nets[$net1]['index'].'_'.$net1; # 4_dmzgovn
		$net2 = $this->nets[$net2]['index'].'_'.$net2; # 11_world

		while (strlen($prefix.$net1.'_'.$net2) > 30) {
			if (strlen($net1) > strlen($net2))
				$net1 = substr($net1, 0, -1);
			else
				$net2 = substr($net2, 0, -1);
		}
		return $prefix.$net1.'_'.$net2;
	}

	function cfgerror($message)
	{
		printf("%s[%d]: %s\n", $this->filename, $this->line, $message);
		return false;
	}

	function FwCfg($filename = 'fw.cfg', $template = '_scripts/fw-template.txt', $cwd = '/etc/firewall')
	{
		$this->filename = $filename;
		$this->template = $template;
		$this->cwd = $cwd;
	}

	function load_cfg()
	{

		$this->line = 0;

		$this->nets = array();

		$success = true;

		chdir($this->cwd);
		$cfg = fopen($this->filename, 'r');
		if (!$cfg) {
			print 'Cannot open '.$this->filename;
			return false;
		}
		while (!feof($cfg)) {
			$this->line++;
			$command = strtolower(fgets($cfg));
			$command = preg_replace('/\#.*/', '', $command);
			$command = preg_replace('/^\s+/', '', $command);
			$command = preg_replace('/\s+$/', '', $command);
			$command = preg_replace('/\s+/', ' ', $command);

			if (preg_match('/^net (\S+) (.+)$/i', $command, $parts)) {
				# net interconnect 10.17.255.0/24, 10.16.10.0/24
				$netname = $parts[1];
				if (array_key_exists($netname, $this->nets)) {
					$success = self::cfgerror('Siet '.$netname.' uz bola raz zadefinovana!!!');
					continue;
				}
				$this->nets[$netname] = array(
					'ranges'=>array(), # ranges belonging to this network
					'incomings'=>array(), # from what interfaces the packet might come with this source address
					'rules_to'=>array(), # firewall rules sorted by the destination networks
					'snat_to'=>array(), # snat rules by the destination networks
					'dnat'=>array(), # dnat rules
					'index'=>1+count(array_keys($this->nets)) # index for unique chain names
				);
				$ranges = preg_split('/ ?, ?/', $parts[2]);

				foreach($ranges as $range) {
					if (preg_match('/^\d+\.\d+\.\d+\.\d+\/\d+$/', $range))
						array_push($this->nets[$netname]['ranges'], $range);
					else
						$success = self::cfgerror('Invalid address range '.$range.' for network '.$netname.' (must be x.x.x.x/x)');
				}
			} elseif (preg_match('/^incoming (\S+) (.*)$/', $command, $parts)) {
				# incoming interconnect lan0.92, lan0.502, lan0.902, lan0.903, lan0.904, lan0.905
				$netname = $parts[1];
				if (!array_key_exists($netname, $this->nets)) {
					$success = self::cfgerror('Network '.$netname.' must be defined first!');
					continue;
				}
				$incomings = preg_split('/ ?, ?/', $parts[2]);
				foreach ($incomings as $incoming) {
					if (preg_match('/^[0-9a-z\.]+$/', $incoming))
						array_push($this->nets[$netname]['incomings'], $incoming);
					else
						$success = self::cfgerror('Invalid input interface '.$incoming.' for network '.$netname.' (usually like net0.x)');
				}
			} elseif (preg_match('/^route (\S+) gw (\d+\.\d+\.\d+\.\d+)$/', $command, $parts)) {
				# route printers gw 10.17.255.6
				$netname = $parts[1];
				if (!array_key_exists($netname, $this->nets)) {
					$success = self::cfgerror('Network '.$netname.' must be defined first!');
					continue;
				}
				if (array_key_exists('gw', $this->nets[$netname])) {
					$success = self::cfgerror('Network '.$netname.' already has a different gateway!');
					continue;
				}
				$this->nets[$netname]['gw'] = $parts[2];
			} elseif ($command == '') {
			} else {
					$success = self::cfgerror('Unknown command');
			}

		}
		fclose($cfg);
		return $success;
	}

	function load_include_fw($net1, $net2)
	{
		$file = @fopen($net1.'/'.$net2, 'r');
		if (!$file)
			return false;
		while (!feof($file)) {
			$line = fgets($file);
			$line = preg_replace('/\#.*/', '', $line);
			$line = preg_replace('/^\s+/', '', $line);
			$line = preg_replace('/\s+$/', '', $line);
			$line = preg_replace('/\s+/', ' ', $line);
			if ($line == '')
				continue;
			array_push($this->nets[$net1]['rules_to'][$net2], $line);
		}
		fclose($file);
		return true;
	}

	function load_include_snat($net1, $net2)
	{
		$file = @fopen($net1.'/'.$net2.'.snat', 'r');
		if (!$file)
			return false;
		while (!feof($file)) {
			$line = fgets($file);
			$line = preg_replace('/\#.*/', '', $line);
			$line = preg_replace('/^\s+/', '', $line);
			$line = preg_replace('/\s+$/', '', $line);
			$line = preg_replace('/\s+/', ' ', $line);
			if ($line == '')
				continue;
			array_push($this->nets[$net1]['snat_to'][$net2], $line);
		}
		fclose($file);
		return true;
	}

	function load_include_dnat($net)
	{
		$file = @fopen($net.'.dnat', 'r');
		if (!$file)
			return false;
		while (!feof($file)) {
			$line = fgets($file);
			$line = preg_replace('/\#.*/', '', $line);
			$line = preg_replace('/^\s+/', '', $line);
			$line = preg_replace('/\s+$/', '', $line);
			$line = preg_replace('/\s+/', ' ', $line);
			if ($line == '')
				continue;
			array_push($this->nets[$net]['dnat'], $line);
		}
		fclose($file);
		return true;
	}

	function load_extra($table, $chain, $filename)
	{
		$file = @fopen($filename, 'r');
		if (!$file)
			return false;

		$this->extras[$table][$chain] = array();

		while (!feof($file)) {
			$line = fgets($file);
			$line = preg_replace('/\#.*/', '', $line);
			$line = preg_replace('/^\s+/', '', $line);
			$line = preg_replace('/\s+$/', '', $line);
			$line = preg_replace('/\s+/', ' ', $line);
			if ($line == '')
				continue;
			array_push($this->extras[$table][$chain], $line);
		}
		fclose($file);
		return true;
	}

	function load_extras()
	{
		chdir($this->cwd.'/_extras');
		foreach(glob('{fw,nat}-*', GLOB_BRACE) as $filename) {
			list ($table,$chain) = explode('-', $filename, 2);
			self::load_extra($table, $chain, $filename);
		}
		chdir($this->cwd);
	}

	function load_includes()
	{
		chdir($this->cwd);

		foreach (array_keys($this->nets) as $net1) {
			foreach (array_keys($this->nets) as $net2) {
				$this->nets[$net1]['rules_to'][$net2] = array();
				$this->nets[$net1]['snat_to'][$net2] = array();
				self::load_include_fw($net1,$net2);
				self::load_include_snat($net1,$net2);
			}
			self::load_include_dnat($net1);
		}
	}

	function list_nets()
	{
		print 'Known networks: '.join(', ', array_keys($this->nets))."\n";
	}

	function save_iptables()
	{
		$tmpl = fopen($this->template, 'r');
		if (!$tmpl)
			return false;
		$rules = "";
		while (!feof($tmpl)) {
			$line = fgets($tmpl);
			if ($line == "<<NAT_DNAT_NAMES>>\n") { ###### DNAT
				foreach (array_keys($this->nets) as $net)
					$rules .= ':'.$this->net_to_chain('I', $net)." - [0:0]\n";
			} elseif ($line == "<<NAT_DNAT_RULES>>\n") {
				foreach (array_keys($this->nets) as $net) {
					foreach ($this->nets[$net]['dnat'] as $dnatrule)
						$rules .= '-A '.$this->net_to_chain('I', $net)." ".$dnatrule."\n";
					$rules .= '-A '.$this->net_to_chain('I', $net)." -j ACCEPT\n";
				}
			} elseif ($line == "<<NAT_PREROUTING_RULES>>\n") {
				foreach (array_keys($this->nets) as $net) {
					foreach ($this->nets[$net]['ranges'] as $dnatrange)
						$rules .= '-A PREROUTING -s '.$dnatrange.' -j '.$this->net_to_chain('I', $net)."\n";
				}
			} else if ($line == "<<NAT_SNAT_NAMES>>\n") { ###### SNAT
				foreach (array_keys($this->nets) as $net1)
					foreach (array_keys($this->nets) as $net2)
						$rules .= ':'.$this->nets_to_chain('O', $net1, $net2)." - [0:0]\n";
			} else if ($line == "<<NAT_SNAT_RULES>>\n") {
				foreach (array_keys($this->nets) as $net1)
					foreach (array_keys($this->nets) as $net2) {
						foreach ($this->nets[$net1]['snat_to'][$net2] as $snatrule)
							$rules .= '-A '.$this->nets_to_chain('O', $net1, $net2)." ".$snatrule."\n";
						$rules .= '-A '.$this->nets_to_chain('O', $net1, $net2)." -j ACCEPT\n";
					}
			} elseif ($line == "<<NAT_POSTROUTING_RULES>>\n") {
				foreach (array_keys($this->nets) as $net1) {
					foreach (array_keys($this->nets) as $net2)
						foreach ($this->nets[$net1]['ranges'] as $snatrange_src)
							foreach ($this->nets[$net2]['ranges'] as $snatrange_dst)
								$rules .= '-A POSTROUTING -s '.$snatrange_src.' -d '.$snatrange_dst.' -j '.$this->nets_to_chain('O', $net1, $net2)."\n";
					foreach ($this->nets[$net1]['ranges'] as $snatrange_src)
						$rules .= '-A POSTROUTING -s '.$snatrange_src." -j ACCEPT\n";
				}
			} else if ($line == "<<FW_NAMES>>\n") { ###### FORWARD
				foreach (array_keys($this->nets) as $net1)
					foreach (array_keys($this->nets) as $net2)
						$rules .= ':'.$this->nets_to_chain('F', $net1, $net2)." - [0:0]\n";
				foreach (array_keys($this->extras['fw']) as $chain)
					$rules .= ':'.$chain." - [0:0]\n";
			} else if ($line == "<<FW_RULES>>\n") {
				foreach (array_keys($this->extras['fw']) as $chain)
					foreach ($this->extras['fw'][$chain] as $fwrule)
						$rules .= '-A '.$chain.' '.$fwrule."\n";
					$rules .= '-A '.$chain.' -j RETURN'."\n";

				foreach (array_keys($this->nets) as $net1) {
					foreach (array_keys($this->nets) as $net2) {
						foreach ($this->nets[$net1]['rules_to'][$net2] as $fwrule)
							$rules .= '-A '.$this->nets_to_chain('F', $net1, $net2)." ".$fwrule."\n";
						$rules .= '-A '.$this->nets_to_chain('F', $net1, $net2)." -m limit --limit 5/sec --limit-burst 10 -j LOG --log-ip-options --log-tcp-options --log-level debug --log-prefix \"from_".$net1."_to_".$net2." \"\n";
						$rules .= '-A '.$this->nets_to_chain('F', $net1, $net2)." -j ".$this->default_fw_rule."\n";
					}
				}
			} elseif ($line == "<<FW_FORWARD_RULES>>\n") {
				foreach (array_keys($this->nets) as $net1) {
					foreach (array_keys($this->nets) as $net2)
						foreach ($this->nets[$net1]['ranges'] as $range_src) {
							foreach ($this->nets[$net2]['ranges'] as $range_dst)
								$rules .= '-A FORWARD -s '.$range_src.' -d '.$range_dst.' -j '.$this->nets_to_chain('F', $net1, $net2)."\n";
						}
					foreach ($this->nets[$net1]['ranges'] as $range_src) {
						$rules .= "-A FORWARD -s ".$range_src." -m limit --limit 5/sec --limit-burst 10 -j LOG --log-ip-options --log-tcp-options --log-level debug --log-prefix \"from_".$net1."_to_UNDEF \"\n";
						$rules .= "-A FORWARD -s ".$range_src." -j DROP\n";
					}
				}
				$rules .= "-A FORWARD -m limit --limit 5/sec --limit-burst 10 -j LOG --log-ip-options --log-tcp-options --log-level debug --log-prefix \"from_UNDEF \"\n";
				$rules .= "-A FORWARD -j DROP\n";
			} elseif ($line == "<<FW_CHECKIF_RULES>>\n") {
				$ifaces = array();
				foreach (array_keys($this->nets) as $net)
					$ifaces = array_unique(array_merge($ifaces, $this->nets[$net]['incomings']));
				foreach ($ifaces as $iface) {
					foreach (array_keys($this->nets) as $net) {
						if (in_array($iface, $this->nets[$net]['incomings']))
							$result = 'RETURN';
						else 
							$result = 'DROP';
						foreach ($this->nets[$net]['ranges'] as $range)
							$rules .= '-A check_if -i '.$iface.' -s '.$range.' -j '.$result."\n";
					}
					$rules .= '-A check_if -i '.$iface." -j DROP\n";
				}
				$rules .= "-A check_if -j log_drop\n";
			} else
				$rules .= $line;
		}
		return $rules;
	}

	function save_routes()
	{
		$routes = "";

		$routes .= "# automatically generated. Do not edit.\n";
		foreach (array_keys($this->nets) as $net) {
			if (!array_key_exists('gw', $this->nets[$net]))
				continue;
			foreach ($this->nets[$net]['ranges'] as $range)
				$routes .= "\$IP route add ".$range." via ".$this->nets[$net]['gw']."\n";
		}
		return $routes;
	}
}

$fwcfg = new FwCfg();

$fwcfg->load_cfg();
$fwcfg->load_includes();
$fwcfg->load_extras();

while ($argc > 1) {
	if ($argv[1] == '--help') {
		print "Command line arguments:\n";
		print "--help      displays this message\n";
		print "--info      displays the information, does not apply anything\n";
		print "--dump      displays fw rules\n";
		print "--dump-routes displays routes\n";
		// print "--apply     applies fw rules\n";
		print "\n";
		print "--debug      displays variable dump suitable for debugging :)\n";
	} elseif ($argv[1] == '--info') {
		$fwcfg->list_nets();
	} elseif ($argv[1] == '--dump') {
		$var = $fwcfg->save_iptables();
		print $var;
	} elseif ($argv[1] == '--dump-routes') {
		$var = $fwcfg->save_routes();
		print $var;
	} elseif ($argv[1] == '--apply') {
		$var = $fwcfg->save_iptables();
		// TODO XXX
	} elseif ($argv[1] == '--debug') {
		print_r($fwcfg->nets);
	} else {
		print "Wrong argument. Try --help\n";
	}
	array_shift($argv);
	$argc--;
}

?>
