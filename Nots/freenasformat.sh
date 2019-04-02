#!/bin/bash
for i in {1..24}
do
echo "sg_format --format --size=512 --six /dev/da$i &"
done
