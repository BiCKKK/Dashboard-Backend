from mininet.node import Switch, Host
import subprocess

class eBPFHost(Host):
    def config(self, **params):
        r = super(eBPFHost, self).config(**params)

        print(f"Configuring eBPFHost {self.name}")
        print(f"Default Interface: {self.defaultIntf()}")

        # Disable offloading
        if self.defaultIntf():
            for off in ["rx", "tx", "sg"]:
                cmd = f"/sbin/ethtool --offload {self.defaultIntf()} {off} off"
                print(f"Running command: {cmd}")
                self.cmd(cmd)
        else:
            print(f"Warning: No default interface found for host {self.name}")

        return r

class eBPFSwitch(Switch):
    dpid = 1

    def __init__(self, name, switch_path='softswitch', dpid=None, **kwargs):
        Switch.__init__(self, name, str(dpid), **kwargs) #F: Fixed missing DPID argument pass to Mininet 

        self.switch_path = switch_path

        if dpid:
            self.dpid = dpid
            eBPFSwitch.dpid = max(eBPFSwitch.dpid, dpid)
        else:
            self.dpid = eBPFSwitch.dpid
            eBPFSwitch.dpid += 1

    @classmethod
    def setup(cls):
        pass

    def start(self, controllers):
        print("Starting eBPF switch", self.name)

        args = [self.switch_path]

        args.extend(['-p', '-i', '--dpid', str(self.dpid)])

        for port, intf in self.intfs.items():
            if not intf.IP():
                args.append(intf.name)

        self.proc = subprocess.Popen(args)

    def stop(self):
        print('stopping')
        self.proc.kill()
