#!/usr/bin/env bash
# Builds a fake Linux module environment (a /proc/modules file, a /sys/module
# tree and a modules.dep) so the detector can be tested deterministically
# without root, without a real kernel and without loading any module.
#
#   fx_init DIR                     start an empty system in DIR
#   fx_base_system                  populate a typical clean system
#   fx_add NAME SIZE REF DEPS SRCVERSION [TAINT] [MODDEP_PATH|none] [STATE]
#   fx_remove NAME                  unload a module (everywhere)
#   fx_hide_proc NAME               remove it from /proc/modules only
#   fx_hide_sys NAME                remove it from /sys/module only
#   fx_set_srcversion NAME VALUE    simulate a replaced module binary
#   fx_set_size NAME SIZE
#   detector_args                   common flags to point the detector at DIR

FX=""

fx_init() {
    FX="$1"
    rm -rf "$FX"
    mkdir -p "$FX/sys"
    : > "$FX/proc_modules"
    : > "$FX/modules.dep"
}

fx_add() {
    local name=$1 size=$2 ref=$3 deps=$4 src=$5 taint=${6:-}
    local path=${7:-kernel/drivers/$1.ko} state=${8:-Live}
    local line="$name $size $ref $deps $state 0xffffffffc0000000"
    [ -n "$taint" ] && line="$line ($taint)"
    echo "$line" >> "$FX/proc_modules"

    local d="$FX/sys/$name"
    mkdir -p "$d/holders" "$d/parameters"
    echo live > "$d/initstate"
    echo "$taint" > "$d/taint"
    echo "$src" > "$d/srcversion"
    echo "1.0" > "$d/version"
    echo $((size - 512)) > "$d/coresize"
    echo 512 > "$d/initsize"
    [ "$path" != none ] && echo "$path:" >> "$FX/modules.dep"
    return 0
}

fx_remove() {
    grep -v "^$1 " "$FX/proc_modules" > "$FX/proc.tmp" || true
    mv "$FX/proc.tmp" "$FX/proc_modules"
    rm -rf "${FX:?}/sys/$1"
    grep -v "/$1\.ko:" "$FX/modules.dep" > "$FX/dep.tmp" || true
    mv "$FX/dep.tmp" "$FX/modules.dep"
}

fx_hide_proc() {
    grep -v "^$1 " "$FX/proc_modules" > "$FX/proc.tmp" || true
    mv "$FX/proc.tmp" "$FX/proc_modules"
}

fx_hide_sys() { rm -rf "${FX:?}/sys/$1"; }

fx_set_srcversion() { echo "$2" > "$FX/sys/$1/srcversion"; }

fx_set_size() {
    sed -i.bak "s/^$1 [0-9]* /$1 $2 /" "$FX/proc_modules" && rm -f "$FX/proc_modules.bak"
    echo $(($2 - 512)) > "$FX/sys/$1/coresize"
}

fx_base_system() {
    fx_add ext4          729088 1 "mbcache,jbd2," "A1B2C3D4E5F6A7B8C9D0E1F" "" "kernel/fs/ext4/ext4.ko.xz"
    fx_add jbd2          163840 1 "ext4,"         "B2C3D4E5F6A7B8C9D0E1F2A" "" "kernel/fs/jbd2/jbd2.ko.xz"
    fx_add mbcache        16384 1 "ext4,"         "C3D4E5F6A7B8C9D0E1F2A3B" "" "kernel/fs/mbcache.ko.xz"
    fx_add nf_tables     286720 91 "nft_chain_nat,nft_ct," "D4E5F6A7B8C9D0E1F2A3B4C" "" "kernel/net/netfilter/nf_tables.ko.xz"
    fx_add nfnetlink      20480 2 "nf_tables,"    "E5F6A7B8C9D0E1F2A3B4C5D" "" "kernel/net/netfilter/nfnetlink.ko.xz"
    fx_add e1000         155648 0 "-"             "F6A7B8C9D0E1F2A3B4C5D6E" "" "kernel/drivers/net/ethernet/intel/e1000/e1000.ko.xz"
    fx_add snd_hda_intel  57344 3 "snd_hda_codec," "A7B8C9D0E1F2A3B4C5D6E7F" "" "kernel/sound/pci/hda/snd-hda-intel.ko.xz"
    fx_add usbhid         65536 0 "-"             "B8C9D0E1F2A3B4C5D6E7F8A" "" "kernel/drivers/hid/usbhid/usbhid.ko.xz"
    fx_add br_netfilter   32768 0 "-"             "D0E1F2A3B4C5D6E7F8A9B0C" "" "kernel/net/bridge/br_netfilter.ko.xz"
}

# Flags that point the detector at the fixture in $FX.
detector_args() {
    printf -- '--proc %s --sys %s --moddep %s --kernel 6.1.0-test --baseline %s' \
        "$FX/proc_modules" "$FX/sys" "$FX/modules.dep" "$FX/baseline.txt"
}
