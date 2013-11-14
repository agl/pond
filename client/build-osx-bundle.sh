#!/bin/sh

rm -Rf Pond.app
contents=Pond.app/Contents
mac=$contents/MacOS
mkdir -p $mac
frameworks=$contents/Frameworks
mkdir -p $frameworks
binary=$mac/Pond
cp -av client $binary
cp -av Info.plist $contents/Info.plist

for lib in $(otool -L ./client | grep '^\t/usr/local' | sed -e 's/^[^\/]*//' -e 's/ .*//'); do
  base=$(basename $lib)
  cp $lib $frameworks
  install_name_tool -change $lib @executable_path/../Frameworks/$base $binary
done
