Vagrant.configure("2") do |config|
  config.vm.box = "debian/bookworm64"
  # Default libvirt network is NAT: the VM has its own kernel + network stack
  # and reaches the internet through the host. Enough for scanning external
  # targets (e.g. scanme.nmap.org). For scanning your LAN you'd need a bridge;
  # vagrant-libvirt's public_network is broken on modern libvirt, so ask if
  # you need it and we'll wire an explicit bridge device instead.

  # Live-mount the project at /vagrant over 9p (no host NFS server needed).
  config.vm.synced_folder ".", "/vagrant", type: "9p", accessmode: "squash"

  config.vm.provider "libvirt" do |lv|
    lv.memory = 1024
    lv.cpus   = 2
  end

  config.vm.provision "shell", inline: <<-SHELL
    apt-get update -q
    apt-get install -y --no-install-recommends gcc make libc6-dev libpcap-dev nmap
  SHELL
end
