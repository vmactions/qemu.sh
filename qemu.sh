#!/usr/bin/env bash

#curl wget screen axel ss lsof netstat zstd jq ssh
#ssh client and ssh server(for sshfs mount)
#rsync
#nfs-kernel-server

set -e


_script_home="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"


_os=""
_release=""
_arch=""

_mem="6144"
_cpu="2"

#virtio-net-device
_nc="e1000"

_sshport="10022"
#attach to ssh console by default
_console=""
_useefi=""
_detach=""
_vpath=""
#number: 0, 1, 2  or "off"
_vnc=""

#sync: sshfs, nfs
_sync=sshfs

#qemu managment port
_qmon=""

#disk type: ide or virtio
_disktype=""

_workingdir="$_script_home/output"

while [ ${#} -gt 0 ]; do
  case "${1}" in
  --os)
    _os="$2"
    shift
    ;;
  --release)
    _release="$2"
    shift
    ;;
  --arch)
    _arch="$2"
    shift
    ;;
  --mem)
    _mem="$2"
    shift
    ;;
  --cpu)
    _cpu="$2"
    shift
    ;;
  --workingdir)
    _workingdir="$2"
    shift
    ;;
  --nc)
    _nc="$2"
    shift
    ;;
  --sshport)
    _sshport="$2"
    shift
    ;;
  --builder)
    _builder="$2"
    shift
    ;;
  --uefi)
    _useefi="1"
    ;;
  --detach | -d)
    _detach="1"
    ;;
  --console|-c)
    _console="1"
    ;;
  -v)
    _vpath="$2"
    shift
    ;;
  --mon)
    _qmon="$2"
    shift
    ;;
  --vnc)
    _vnc="$2"
    shift
    ;;
  --sync)
    _sync="$2"
    shift
    ;;
  --disktype)
    _disktype="$2"
    shift
    ;;
  *)
    echo "Unknown parameter: $1"
    exit 1
    ;;
  esac
  shift 1
done


if [ -z "$_os" ]; then
  echo "use parameters:  --os freebsd  [--release 15.0] [--arch aarch64] [--cpu 2] [--mem 6144] [--sshport 10022] [-v /paht/host:/path/vm] [--workingdir /path/to/data] [--vnc 'num' |off] [--sync sshfs|nfs|rsync] [--disktype ide|virtio] [--uefi] [--detach | -d | --console | -c ]"
  exit 1
fi


if [ "$_os" = "freebsd" ]; then
  _useefi=1
fi


_hostarch="$(uname -m)"
if [ -z "${_arch}" ]; then
  echo "Use host arch: $_hostarch"
  _arch="$_hostarch"
fi


if [ "$_arch" = "x86_64" ] || [ "$_arch" = "amd64" ]; then
  _arch=""
fi
if [ "$_arch" = "arm" ] || [ "$_arch" = "arm64" ]; then
  _arch="aarch64"
fi



builder="vmactions/${_os}-builder"



working="$_workingdir"



_endswith() {
  _str="$1"
  _sub="$2"
  echo "$_str" | grep -- "$_sub\$" >/dev/null 2>&1
}

check_url_exists() {
  url=$1
  http_status=$(curl -o /dev/null --silent --head --write-out '%{http_code}' "$url")
  if [[ "$http_status" -ge 200 && "$http_status" -lt 400 ]]; then
    return 0
  else
    return 1
  fi
}


mkdir -p "$working/${_os}"


echo "Using arch: $_arch"



if [ "$_builder" ]; then
  echo "Builder version: $_builder"
  if [ -z "$_release" ]; then
    _meta="https://api.github.com/repos/$builder/releases/tags/v$_builder"
    _metafile="$working/${_os}/meta.json"
    curl -L "$_meta" >"$_metafile"
    if [ "$_arch" ]; then
     _release="$(cat "$_metafile"  |  jq -r '.assets[].browser_download_url' | grep ${_arch}.qcow2.zst | sort -r | head -1 | cut -d '/' -f 9 | cut -d - -f 2 )"
    else
     _release="$(cat "$_metafile"  |  jq -r '.assets[].browser_download_url' | grep qcow2.zst | sort -r | head -1 | cut -d '/' -f 9 | cut -d - -f 2 | rev | cut -d . -f 3- | rev)"
    fi
  fi
  if [ "$_arch" ]; then
    zst_link="https://github.com/$builder/releases/download/v$_builder/$_os-${_release}-${_arch}.qcow2.zst"
  else
    zst_link="https://github.com/$builder/releases/download/v$_builder/$_os-${_release}.qcow2.zst"
  fi
fi


allReleases="$working/${_os}/all.json"


if [ -z "$_release" ]; then
  curl -L "https://api.github.com/repos/$builder/releases" >"$allReleases"
  if [ "$_arch" ]; then
    _release="$(cat "$allReleases"  |  jq -r '.[].assets[].browser_download_url' | grep ${_arch}.qcow2.zst | sort -r | head -1 | cut -d '/' -f 9 | cut -d - -f 2 )"
  else
    _release="$(cat "$allReleases"  |  jq -r '.[].assets[].browser_download_url' | grep qcow2.zst | sort -r | head -1 | cut -d '/' -f 9 | cut -d - -f 2 | rev | cut -d . -f 3- | rev)"
    if [ -z "$_release" ]; then
      _release="$(cat "$allReleases"  |  jq -r '.[].assets[].browser_download_url' | grep qcow2.xz | sort -r | head -1 | cut -d '/' -f 9 | cut -d - -f 2 | rev | cut -d . -f 3- | rev)"
    fi
  fi
fi

echo "Using release: $_release"
  
  
if [ -z "$zst_link" ]; then
  if [ ! -e "$allReleases" ]; then
    curl -L "https://api.github.com/repos/$builder/releases" >"$allReleases"
  fi
  
  if [ -z "$_arch" ] || [ "$_arch" = "x86_64" ]; then
    zst_link="$(cat "$allReleases"  |  jq -r '.[].assets[].browser_download_url' | grep "${_os}-${_release}".qcow2.zst'$' | sort -r | head -1)"
    if [ -z "$zst_link" ]; then
      zst_link="$(cat "$allReleases"  |  jq -r '.[].assets[].browser_download_url' | grep "${_os}-${_release}".qcow2.xz'$' | sort -r | head -1)"
    fi
  else
    zst_link="$(cat "$allReleases"  |  jq -r '.[].assets[].browser_download_url' | grep "${_os}-${_release}-${_arch}".qcow2.zst'$'| sort -r | head -1)"
  fi
fi


echo "Using zst_link: $zst_link"

if [ -z "$zst_link" ]; then
  echo "can not find the zst file link."
  exit 1
fi

if [ -z "$_builder" ]; then
  _builder=$(echo "$zst_link" | cut -d / -f 8 | tr -d v)
  echo "Builder ver: $_builder"
fi


_output="$working/${_os}/v${_builder}"
mkdir -p "$_output"


ovafile="$(echo "$zst_link" | rev  | cut -d / -f 1 | rev)"
qow2="$(echo "$zst_link" | rev  | cut -d / -f 1 | cut -d . -f 2- | rev)"
 

if [ ! -e "$_output/$qow2" ]; then
  if [ ! -e "$_output/$ovafile" ]; then
    echo "Downloading $zst_link"
    axel -q -n 8 -o "$_output/$ovafile"  "$zst_link"
    
    for i in $(seq 1 9) ; do
      _url="${zst_link}.$i"
      echo "Checking $_url"
      if ! check_url_exists "$_url"; then
        echo "break"
        break
      fi
      axel -q -n 8 -o "$_output/${ovafile}.$i"  "$_url"
      ls -lah
      cat "$_output/${ovafile}.$i" >>"$_output/$ovafile"
      rm -f "$_output/${ovafile}.$i"
    done
  fi
  echo "Extracting"
  if _endswith "$zst_link" ".xz"; then
    #just to keep compatible with the old xz editions
    xz -v -d -c "$_output/$ovafile" >"$_output/$qow2"
  else
    zstd -d "$_output/$ovafile" -o "$_output/$qow2"
  fi
  echo "Extract finished"
fi


_name="$_os-$_release"
if [ "$_arch" ]; then
  _name="$_os-$_release-$_arch"
fi


###############################################
_hostid_link="https://github.com/vmactions/${_os}-builder/releases/download/v${_builder}/${_name}-host.id_rsa"

echo "Host id link: $_hostid_link"
_hostid="$_output/$(echo "$_hostid_link" | rev | cut -d / -f 1 | rev)"
echo "Host id file: $_hostid"

if [ ! -e "$_hostid" ]; then
 curl -L  "$_hostid_link" >"$_hostid"
 chmod 600 "$_hostid"
fi


_vmpub_link="https://github.com/vmactions/${_os}-builder/releases/download/v${_builder}/${_name}-id_rsa.pub"

echo "VM pub key link: $_vmpub_link"
_vmpub="$_output/$(echo "$_vmpub_link" | rev | cut -d / -f 1 | rev)"
if [ ! -e "$_vmpub" ]; then
  echo "VM pub key file: $_vmpub"
  curl -L  "$_vmpub_link" >"$_vmpub"
fi



ls -lah "$_output"

##############################################





_qowfull="$_output/$qow2"


if [ -z "$_disktype" ]; then
  if [ "$_os" = "dragonflybsd" ]; then
    _disktype="ide"
  else
    _disktype="virtio"
  fi
fi


_qemu_args=" -serial mon:stdio 
-name $_name 
-smp ${_cpu:-2} 
-m ${_mem:-6144} 
-netdev user,id=net0,net=192.168.122.0/24,dhcpstart=192.168.122.50,hostfwd=tcp::${_sshport:-10022}-:22
-drive file=${_qowfull},format=qcow2,if=${_disktype} "

if [ "$_qmon" ]; then
  _qemu_args="-monitor telnet:localhost:$_qmon,server,nowait,nodelay  $_qemu_args "
fi

if [ "$_vnc" != "off" ]; then
  if [ -z "$_vnc" ]; then
    if command -v ss; then
      _vnc=$(ss -4ntpl | grep :590 | wc -l)
    elif command -v lsof; then
      _vnc=$(lsof -i4 -sTCP:LISTEN -n -P | grep :590 | wc -l)
    elif command -v netstat; then
      _vnc=$(netstat -ntpl4 | grep :590 | wc -l)
    else
      _vnc=0
    fi
  fi
  _qemu_args=" -display vnc=:$_vnc  $_qemu_args "
fi




_qemu_bin="qemu-system-x86_64"

if [ "$_arch" = "aarch64" ]; then
  _qemu_bin="qemu-system-aarch64"

  _efi="$_output/$_name-QEMU_EFI.fd"
  if [ ! -e "$_efi" ]; then
    dd if=/dev/zero of="$_efi" bs=1M count=64
    dd if=/usr/share/qemu-efi-aarch64/QEMU_EFI.fd of="$_efi" conv=notrunc
  fi
  _efivars="$_output/$_name-QEMU_EFI_VARS.fd"
  if [ ! -e "$_efivars" ]; then
    dd if=/dev/zero of="$_efivars" bs=1M count=64
  fi

  _qemu_args="$_qemu_args -device ${_nc:-e1000},netdev=net0 \
  -device virtio-balloon-device "

  if [ "${_hostarch}" = "aarch64" ]; then
    #run arm64 on arm64
    if [ -e "/dev/kvm" ]; then
      _qemu_args="$_qemu_args -machine virt,accel=kvm,gic-version=3 
    -cpu host,kvm=on,
    -rtc base=utc 
    -enable-kvm -global kvm-pit.lost_tick_policy=discard 
    -global kvm-pit.lost_tick_policy=discard  
    -drive if=pflash,format=raw,readonly=on,file=${_efi}
    -drive if=pflash,format=raw,file=${_efivars}
    "
    else
      _qemu_args="$_qemu_args -machine virt,accel=tcg,gic-version=3 
    -cpu host
    -rtc base=utc 
    -drive if=pflash,format=raw,readonly=on,file=${_efi}
    -drive if=pflash,format=raw,file=${_efivars}
    "
    fi
  else
    #run arm64 on x86
    _qemu_args="$_qemu_args -machine virt,accel=tcg,gic-version=3 
    -cpu max
    -rtc base=utc 
    -drive if=pflash,format=raw,readonly=on,file=${_efi}
    -drive if=pflash,format=raw,file=${_efivars}
    "
    
  fi

else
  _qemu_args="$_qemu_args -device ${_nc:-e1000},netdev=net0,bus=pci.0,addr=0x3 
  -device virtio-balloon-pci,bus=pci.0,addr=0x6 "

  if [ "${_hostarch}" = "x86_64" ]; then
    #run x86 on x86
    if [ -e "/dev/kvm" ]; then
      _qemu_args="$_qemu_args -machine pc,accel=kvm,hpet=off,smm=off,graphics=off,vmport=off 
    -enable-kvm -global kvm-pit.lost_tick_policy=discard 
    -global kvm-pit.lost_tick_policy=discard 
    -cpu host,kvm=on,l3-cache=on,+hypervisor,migratable=no,+invtsc 
    -rtc base=utc,driftfix=slew "
    else
      _qemu_args="$_qemu_args -machine pc,accel=tcg,hpet=off,smm=off,graphics=off,vmport=off 
    -cpu qemu64 
    -rtc base=utc,driftfix=slew "
    fi
    if [ "$_useefi" ]; then
      _efi="/usr/share/qemu/OVMF.fd"
      _efivars="$_output/$_name-OVMF_VARS.fd"
      if [ ! -e "$_efivars" ]; then
        dd if=/dev/zero of="$_efivars" bs=1M count=4
      fi
      _qemu_args="$_qemu_args -drive if=pflash,format=raw,readonly=on,file=${_efi}
    -drive if=pflash,format=raw,file=${_efivars}
    "
    fi
  else
    echo "not implemented"
    exit 1
  fi
fi


echo "_qemu_bin=$_qemu_bin"
echo "_qemu_args=$_qemu_args"



#########################################

CONSOLE_NAME="$_name-console"
CONSOLE_FILE="$_output/$_name-console.log"
  
  



rm -f "$CONSOLE_FILE"
screen -dmLS "$CONSOLE_NAME" -Logfile "$CONSOLE_FILE" -L $_qemu_bin $_qemu_args

(
#press enter key to speed up booting
for i in $(seq 0 9) ; do
  screen -S "$CONSOLE_NAME" -p 0 -X stuff "\r"
  sleep 1
done
)&

sleep 1

if screen -ls | grep -q "$CONSOLE_NAME"; then
  echo "QEMU started."
else
  echo "QEMU start error: "
  cat "$CONSOLE_FILE"
  exit 1
fi

####################################




_initInVM() {
  _showlog="$1"
  #initialize file mounting
  if [ "$_showlog" ]; then
    tail -F "$CONSOLE_FILE"&
    _tailid="$!"
  fi

  #init ssh
  mkdir -p ~/.ssh
  chmod 700 ~/.ssh
  cat "$_vmpub" >> ~/.ssh/authorized_keys
  touch ~/.ssh/config
  if ! grep "Include config.d" ~/.ssh/config >/dev/null; then
    echo 'Include config.d/*.conf' >>~/.ssh/config
  fi
  
  mkdir -p ~/.ssh/config.d
  echo "

Host $_name  $_sshport
  LogLevel ERROR
  StrictHostKeyChecking no
  SendEnv   CI  GITHUB_* 
  UserKnownHostsFile=/dev/null
  User root
  HostName localhost
  Port $_sshport
  IdentityFile=$_hostid
  
">~/.ssh/config.d/$_name.conf
  chmod 600 ~/.ssh/config

  _retry=0
  while ! timeout 2 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -i "$_hostid" -p "${_sshport}" root@localhost exit >/dev/null 2>&1; do
    echo "vm is booting just wait."
    sleep 2
    _retry=$(($_retry + 1))
    if [ $_retry -gt 300 ]; then
      echo "Boot failed."
      return 1
    fi
  done
  if [ "$_showlog" ]; then
    kill "$_tailid"
  fi
  echo "Boot ready"

  if [ "$_console" ]; then
    echo "======================================"
    echo ""
    echo "You can login the vm with: ssh $_name"
    echo "Or just:  ssh $_sshport"
    echo "======================================"
  fi
  ssh "${_sshport}" sh "cat - >.ssh/config" <<EOF
StrictHostKeyChecking=no

Host host
  HostName  192.168.122.2
  User $USER
  ServerAliveInterval 1

EOF

  if [ "$_vpath" ]; then
    _vhost="$(echo "$_vpath" | cut -d : -f 1)"
    echo "Mount host dir: $_vhost"
    _vguest="$(echo "$_vpath" | cut -d : -f 2)"
    echo "Mount to guest dir: $_vguest"

    _retry=0
    if [ "$_sync" = "sshfs" ] || [ -z "$_sync" ]; then
      while ! _syncSSHFS "$_vhost" "$_vguest"; do
        echo "error sshfs, let try again"
        sleep 2
        _retry=$(($_retry + 1))
        if [ $_retry -gt 10 ]; then
          echo "sshfs failed."
          return 1
        fi
      done
    elif [ "$_sync" = "nfs" ]; then
      while ! _syncNFS "$_vhost" "$_vguest"; do
        echo "error nfs, let try again"
        sleep 2
        _retry=$(($_retry + 1))
        if [ $_retry -gt 10 ]; then
          echo "nfs failed."
          return 1
        fi
      done
    else
      while ! _syncRSYNC "$_vhost" "$_vguest"; do
        echo "error rsync, let try again"
        sleep 2
        _retry=$(($_retry + 1))
        if [ $_retry -gt 10 ]; then
          echo "rsync failed."
          return 1
        fi
      done
    fi

  fi
}


_syncSSHFS() {
  _vhost="$1"
  _vguest="$2"
  ssh "${_sshport}" sh <<EOF
mkdir -p "$_vguest"

if [ "$_os" = "netbsd" ]; then
  if ! /usr/sbin/mount_psshfs host:"$_vhost" "$_vguest" >/dev/null 2>&1; then
    echo "error run sshfs in vm."
    exit 1
  fi
else
  if [ "$_os" = "freebsd" ]; then
    kldload  fusefs
  fi

  if sshfs -o reconnect,ServerAliveCountMax=2,allow_other,default_permissions host:$_vhost $_vguest ; then
    echo "run sshfs in vm is OK, show mount:"
    /sbin/mount
    if [ "$_os" = "netbsd" ]; then
      tree $_vhost
    fi
  else
    echo "error run sshfs in vm."
    exit 1
  fi

fi

echo "ssh finished."

EOF


}

_syncNFS() {
  _vhost="$1"
  _vguest="$2"
  _SUDO=""
  if command -v sudo >/dev/null; then
    _SUDO="sudo"
  fi
  _entry="$_vhost *(rw,insecure,async,no_subtree_check,anonuid=$(id -u),anongid=$(id -g))"
  if ! grep -- "$_vhost" /etc/exports; then
    echo "$_entry" | $_SUDO tee -a /etc/exports
    $_SUDO exportfs -a
    $_SUDO service nfs-server restart
  fi
  echo "Configuring NFS in VM with default command"

  ssh "${_sshport}" sh <<EOF
mkdir -p "$_vguest"
if [ "$_os" = "openbsd" ]; then
  mount -t nfs -o -T 192.168.122.2:$_vhost $_vguest
elif [ -e "/sbin/mount" ]; then
  /sbin/mount 192.168.122.2:$_vhost $_vguest
else
  mount 192.168.122.2:$_vhost $_vguest
fi

EOF
  echo "Done with NFS"

}

_syncRSYNC() {
  _vhost="$1"
  _vguest="$2"

}



if [ "$_console" ]; then
  _initInVM >/dev/null &
  screen -r "$CONSOLE_NAME"
else
  if [ -z "$_detach" ]; then
    _initInVM 1
  else
    _initInVM
  fi
  if [ -z "$_detach" ]; then
    ssh "$_name"
  fi
  echo "======================================"
  echo "The vm is still running."
  echo "You can login the vm with:  ssh $_name"
  echo "Or just:  ssh $_sshport"
  echo "======================================"
fi





