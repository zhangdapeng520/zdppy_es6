echo "导出es6"
docker save -o es6_v1.tar elasticsearch:6.8.23

echo "导出kibana"
docker save -o es6kbn_v1.tar kibana:6.8.23