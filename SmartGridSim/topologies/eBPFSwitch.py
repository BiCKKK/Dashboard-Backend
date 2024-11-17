from mininet.node import Switch, Host
import subprocess

class eBPFHost(Host):
    def config(self, **params):
        r = super().config(**params)

        # Disable offloading
        for off in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload {} {} off".format(self.defaultIntf(), off)
            self.cmd(cmd)

        return r

class eBPFSwitch(Switch):
    dpid_counter = 1

    def __init__(self, name, switch_path='softswitch', dpid=None, **kwargs):
        super().__init__(name, dpid=str(dpid) if dpid else set(eBPFSwitch.dpid), **kwargs)

        self.switch_path = switch_path

        if dpid:
            self.dpid = dpid
            eBPFSwitch.dpid_counter = max(eBPFSwitch.dpid_counter, dpid + 1)
        else:
            self.dpid = eBPFSwitch.dpid_counter
            eBPFSwitch.dpid_counter += 1

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
        print('Stopping eBPF Switch', self.name)
        if hasattr(self, 'proc') and self.proc:
            self.proc.kill()
            self.proc = None
