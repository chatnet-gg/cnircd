#!/bin/sh
# Generates the runtime/ dir to execute tests for meson
# Not to be run manually!

set -eu

# `realpath -s` (no symlink resolution) isn't supported on FreeBSD's
# `realpath` -- plain `cd ... && pwd -P` gets the same absolute,
# already-existing-path result and works on both (bitmaster, 2026-10-21).
SOURCEROOT=$(cd "$1" && pwd -P)
BUILDROOT=$(cd "$2" && pwd -P)
OUTPUT=$(cd "$3" && pwd -P)/runtime

rm -rf $OUTPUT
mkdir -p $OUTPUT/modules/autoload
mkdir $OUTPUT/bin
mkdir $OUTPUT/help

ln -s $BUILDROOT/authd/authd $OUTPUT/bin/authd
ln -s $BUILDROOT/bandb/bandb $OUTPUT/bin/bandb
ln -s $BUILDROOT/ssld/ssld $OUTPUT/bin/ssld

cp -r $SOURCEROOT/help/opers $OUTPUT/help
cp -r $SOURCEROOT/help/users $OUTPUT/help
$SOURCEROOT/help/make_index.SH $SOURCEROOT/help $OUTPUT/help
# `grep -P` (Perl regex) isn't supported on FreeBSD's `grep` -- this
# does the same quoted-list extraction in plain Python instead
# (bitmaster, 2026-10-21).
links=$(python3 "$(dirname "$0")/extract_meson_list.py" "$SOURCEROOT/help/meson.build" user_symlinks)
echo $links | tr ' ' '\n' |  while read link; do
  ln -s "$OUTPUT/help/opers/$link" "$OUTPUT/help/users/$link"
done

coremods=$(python3 "$(dirname "$0")/extract_meson_list.py" "$SOURCEROOT/modules/meson.build" core_modules)
echo $coremods | tr ' ' '\n' | while read link; do
  ln -s "$BUILDROOT/modules/$link.so" "$OUTPUT/modules/$link.so"
done

modules=$(python3 "$(dirname "$0")/extract_meson_list.py" "$SOURCEROOT/modules/meson.build" autoload_modules)
echo $modules | tr ' ' '\n' | while read link; do
  ln -s "$BUILDROOT/modules/$link.so" "$OUTPUT/modules/autoload/$link.so"
done

cp $SOURCEROOT/tests/*.conf $3
echo "Hello World!" > $OUTPUT/motd
