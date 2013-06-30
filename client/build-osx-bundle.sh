rm -Rf Pond.app
mkdir -p Pond.app/Contents/MacOS
frameworks=Pond.app/Contents/Frameworks
mkdir -p $frameworks
binary=Pond.app/Contents/MacOS/Pond
cp -av client $binary

for lib in $(otool -L ./client | grep '^\t/usr/local' | sed -e 's/^[^\/]*//' -e 's/ .*//'); do
  base=$(basename $lib)
  cp $lib $frameworks
  install_name_tool -change $lib @executable_path/../Frameworks/$base $binary
done
