#!/bin/bash
PYTHONENV="aws-cis-elasticsearch-python36-env"
PACKAGENAME="aws_cis_elasticsearch-`date +%Y%m%d`.zip"
source $PYTHONENV/bin/activate
TMPDIR=`mktemp -d`
cp aws_cis_elasticsearch.py aws-cis-elasticsearch-python36-env
for i in `cat deps.txt`; do
	python -m pip install $i -t $TMPDIR/
done


cp aws_cis_elasticsearch.py $TMPDIR
( cd $TMPDIR && zip -r $PACKAGENAME * )
mv $TMPDIR/$PACKAGENAME .
rm -rf $TMPDIR/
