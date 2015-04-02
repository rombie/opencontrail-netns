#!/usr/bin/env ruby

# sudo yum -y install ruby
# sudo ruby < <(curl -s https://raw.githubusercontent.com/rombie/opencontrail-netns/master/provision/fedora/contrail_compute.rb)

require 'socket'
require 'ipaddr'

@ws="#{ENV['HOME']}/contrail"
@intf = "eth1"

def sh(cmd); puts cmd; `#{cmd}`.chomp end
def error(msg); puts msg; exit -1 end

def ssh_setup
    sh("mkdir -p #{ENV['HOME']}/.ssh")
    File.open("#{ENV["HOME"]}/.ssh/config", "a") { |fp|
        conf=<<EOF
UserKnownHostsFile=/dev/null
StrictHostKeyChecking=no
LogLevel=QUIET
EOF
        fp.puts(conf)
    }
    sh("chmod 600 #{ENV['HOME']}/.ssh/config")
end

def initial_setup
    ssh_setup
    @contrail_controller = IPSocket.getaddress("contrail-controller")
    error "Cannot resolve contrail-controller host" if @contrail_controller.empty?
    sh("rm -rf #{@ws}")
    sh("mkdir -p #{@ws}")
    Dir.chdir("#{@ws}")
end

# Download and extract contrail and thirdparty rpms
def download_contrail_software
    sh("wget -qO - https://github.com/rombie/opencontrail-netns/blob/master/provision/fedora/contrail-rpms.tar.xz?raw=true | tar Jx")
    sh("wget -qO - https://github.com/rombie/opencontrail-netns/blob/master/provision/fedora/thirdparty.tar.xz?raw=true | tar Jx")
end

# Install third-party software
def install_thirdparty_software
    third_party_rpms = [
        "#{@ws}/thirdparty/xmltodict-0.7.0-0contrail.el7.noarch.rpm",
        "#{@ws}/thirdparty/consistent_hash-1.0-0contrail0.el7.noarch.rpm",
        "#{@ws}/thirdparty/python-pycassa-1.10.0-0contrail.el7.noarch.rpm ",
    ]

    sh("yum -y install #{third_party_rpms.join(" ")}")
    sh("yum -y install createrepo docker vim git")
end

def install_contrail_software
    contrail_rpms = [
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/python-contrail-3.0-4100.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/python-contrail-vrouter-api-3.0-4100.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-vrouter-utils-3.0-4100.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-vrouter-init-3.0-4100.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-lib-3.0-4100.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-vrouter-3.0-4100.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-vrouter-agent-3.0-4100.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/noarch/contrail-setup-3.0-4100.fc21.noarch.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/noarch/contrail-vrouter-common-3.0-4100.fc21.noarch.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-vrouter-init-3.0-4100.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-utils-3.0-4100.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-nodemgr-3.0-4100.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/noarch/contrail-vrouter-common-3.0-4100.fc21.noarch.rpm",
    ]

    # Install contrail rpms
    sh("yum -y install #{contrail_rpms.join(" ")}")
end

def provision_contrail_compute
    prefix = sh("ip addr show dev eth1|\grep -w inet | \grep -v dynamic | awk '{print $2}'")
    error("Cannot retrieve #{@intf}'s IP address") if prefix !~ /(.*)\/(\d+)$/
    @ip = $1
    msk = IPAddr.new(prefix).pretty_inspect.split("/")[1].chomp.chomp(">")        
    gw = sh(%{netstat -rn |\grep "^0.0.0.0" | awk '{print $2}'})

    ifcfg = <<EOF
#Contrail vhost0
DEVICE=vhost0
ONBOOT=yes
BOOTPROTO=none
IPV6INIT=no
USERCTL=yes
IPADDR=#{ip}
NETMASK=#{msk}
NM_CONTROLLED=no
#NETWORK MANAGER BUG WORKAROUND
SUBCHANNELS=1,2,3
GATEWAY=#{gw}
DNS1=8.8.8.8
#DOMAIN="contrail.juniper.net. juniper.net. jnpr.net. contrail.juniper.net"
EOF
    File.open("/etc/sysconfig/network-scripts/ifcfg-vhost0", "w") { |fp|
        fp.puts(ifcfg)
    }

    sh("sed 's/__DEVICE__/#{@intf}/' /etc/contrail/agent_param.tmpl > /etc/contrail/agent_param")
    sh("sed -i 's/# type=kvm/type=kvm/' /etc/contrail/contrail-vrouter-agent.conf")
    sh("/sbin/ifconfig eth1 |\grep ether | awk '{print $2}' | xargs echo > /etc/contrail/default_pmac")
    sh("sed -i 's/# name=vhost0/name=vhost0/' /etc/contrail/contrail-vrouter-agent.conf")
    sh("sed -i 's/# physical_interface=vnet0/physical_interface=#{@intf}/' /etc/contrail/contrail-vrouter-agent.conf")
    sh("sed -i 's/# server=10.204.217.52/server=#{@contrail_controller}/' /etc/contrail/contrail-vrouter-agent.conf")
    sh("sshpass -p vagrant ssh contrail-controller sudo python /opt/contrail/utils/provision_vrouter.py --host_name #{sh('hostname')} --host_ip #{@ip} --api_server_ip #{contrail_controller} --oper add")
    puts("Please do sudo reboot, followed by")
    puts("sudo service supervisor-vrouter restart; sudo service contrail-vrouter-agent restart")
end

def main
    initial_setup
    download_contrail_software
    install_thirdparty_software
    install_contrail_software
    provision_contrail_compute
end

main
