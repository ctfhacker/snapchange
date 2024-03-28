#/bin/bash
docker run --rm \
  -t \
  -v $PWD:/out \
  --entrypoint "/bin/sh" \
  snapchange_example2_no_patch:target \
  -c "/opt/tiff-4.0.4/build/bin/tiffinfo /out/$1"
