rm -Rf Pond.app
mkdir -p Pond.app/Contents/MacOS
frameworks=Pond.app/Contents/F
resources=Pond.app/Contents/Resources
mkdir -p $frameworks
mkdir $resources
binary=Pond.app/Contents/MacOS/Pond
cellar=/usr/local/Cellar
cp -av client $binary

rewrite_library() {
  for lib in $(otool -L $1 | grep '^\t/usr/local' | sed -e 's/^[^\/]*//' -e 's/ .*//'); do
    base=$(basename $lib)
    if [ ! -f $frameworks/$base ] ; then
      cp $lib $frameworks
    fi
    chmod u+w $1
    install_name_tool -change $lib @executable_path/../F/$base $1
    if [ $(basename $1) != $base ] ; then
      rewrite_library $frameworks/$base
    fi
  done
}

for lib in $(otool -L ./client | grep '^\t/usr/local' | sed -e 's/^[^\/]*//' -e 's/ .*//'); do
  base=$(basename $lib)
  cp $lib $frameworks
  install_name_tool -change $lib @executable_path/../F/$base $binary
  rewrite_library $frameworks/$base
done

pango_etc=$(strings $frameworks/libpango-1.0.0.dylib  | grep usr/local | grep etc)
pango_lib=$(strings $frameworks/libpango-1.0.0.dylib  | grep usr/local | grep lib)

cp -a $(dirname $pango_etc) $resources
cp -a $(dirname $pango_lib) $resources

sed -i -e 's![^ ]*/\([^/ ]*\) !\1 !' $(find $resources -name pango.modules)

mkdir -p $resources/lib/gdk-pixbuf-2.0/2.10.0
cat > $resources/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache << EOF
"../F/libpixbufloader-png.so"
"png" 5 "gdk-pixbuf" "The PNG image format" "LGPL"
"image/png" ""
"png" ""
"\211PNG\r\n\032\n" "" 100


EOF

cp $(find $cellar/gdk-pixbuf -name libpixbufloader-png.so | head -n 1) $frameworks
rewrite_library $frameworks/libpixbufloader-png.so

mkdir -p $resources/share/locale
for dir in $(find $cellar -name locale -type d); do
  cp -a $dir/* $resources/share/locale
done

mkdir -p $resources/share/enchant
cp -a $cellar/enchant/1.6.0/share/enchant/* $resources/share/enchant
mkdir -p $resources/lib/enchant
cp -a $cellar/enchant/1.6.0/lib/enchant/* $resources/lib/enchant
rewrite_library $resources/lib/enchant/libenchant_aspell.so
mkdir -p $resources/lib/aspell-0.60
cp -a $cellar/aspell/0.60.6.1/lib/aspell-0.60/* $resources/lib/aspell-0.60
# When libaspell has a relative prefix directory, it goes crazy. I can't figure out where the crazy is coming from so we just go with it and put the files in the directory that it expects.
mkdir -p $resources/lib/Resources/lib/aspell-0.60
mkdir -p $resources/lib/Resources/lib/Resources/lib/aspell-0.60
(
  cd $resources/lib/Resources/lib/Resources/lib/aspell-0.60
  for x in $(find ../../../../../aspell-0.60 -type f); do
    ln -s $x .
  done
) 

mkdir -p $resources/etc/gtk-3.0
mkdir -p $resources/share/themes
cat > $resources/etc/gtk-3.0/settings.ini << EOF
[Settings]
gtk-theme-name=Adwaita
EOF

cp -a ~/.themes/Adwaita $resources/share/themes


for lib in $(ls -1 $frameworks); do
  ../pathrewrite/pathrewrite $frameworks/$lib
done

cat > Pond.app/Contents/Info.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>Pond</string>
    <key>CFBundleIdentifier</key>
    <string>org.imperialviolet.pond</string>
    <key>CFBundleVersion</key>
    <string>0.1</string>
    <key>CFBundleAllowMixedLocalizations</key>
    <string>true</string>
    <key>CFBundleDevelopmentRegion</key>
    <string>English</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>NSHumanReadableCopyright</key>
    <string>Copyright Pond developers 2013</string>
    <key>CFBundleGetInfoString</key>
    <string>Pond, © 2013 Pond developers</string>
    <key>CFBundleDisplayName</key>
    <string>Pond</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>CFBundleIconFile</key>
    <string>pond.icns</string>
</dict>
</plist>
EOF

cp pond.icns $resources
