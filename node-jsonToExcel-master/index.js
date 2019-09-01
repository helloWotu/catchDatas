/*
 * @Author: ihoey
 * @Date:   2017-11-23 15:07:10
 * @Last Modified by:   ihoey
 * @Last Modified time: 2018-04-17 11:20:15
 */

XLSX = require('xlsx')
json = require('./data')

var title = [
  '昵称',
  'edenID',
  '总分',
  '扫荡数',
  '果实数',
  'dp',
  'id',
  '外域进度',
  '最高层数',
  '科技分'
]
var datas = [
  'nickname',
  'edenID',
  'totalScore',
  'mopUp',
  'fruit',
  'dp',
  'id',
  'outlandProgress',
  'maxExplpreLebel',
  'techSocore'
]

var _data = json.map(e => {
  tmp = {}
  for (var i = 0; i < title.length; i++) {
    Object.assign(tmp, {
      [title[i]]: e[datas[i]]
    })
  }
  return tmp
})

console.log(_data)

var _headers = title
var headers = _headers
  .map((v, i) =>
    Object.assign({}, { v: v, position: String.fromCharCode(65 + i) + 1 })
  )
  .reduce(
    (prev, next) =>
      Object.assign({}, prev, {
        [next.position]: { v: next.v }
      }),
    {}
  )

var data = _data
  .map((v, i) =>
    _headers.map((k, j) =>
      Object.assign(
        {},
        { v: v[k], position: String.fromCharCode(65 + j) + (i + 2) }
      )
    )
  )
  .reduce((prev, next) => prev.concat(next))
  .reduce(
    (prev, next) =>
      Object.assign({}, prev, {
        [next.position]: { v: next.v }
      }),
    {}
  )

// 合并 headers 和 data
var output = Object.assign({}, headers, data)

// 获取所有单元格的位置
var outputPos = Object.keys(output)

// 计算出范围
var ref = outputPos[0] + ':' + outputPos[outputPos.length - 1]

// 构建 workbook 对象
var wb = {
  SheetNames: ['mySheet'],
  Sheets: {
    mySheet: Object.assign({}, output, { '!ref': ref })
  }
}

// 导出 Excel
XLSX.writeFile(wb, '20190901.xlsx')
