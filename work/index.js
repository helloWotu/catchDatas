XLSX = require('xlsx')
namesJson = require('./jsons/allNames.json')
dpsData = require('./jsons/dpsData.json')
const PCAPNGParser = require('pcap-ng-parser')
const pcapNgParser = new PCAPNGParser()
const myFileStream = require('fs').createReadStream(
  './pcapng/20191027.pcapng'
)

const ip = '139.196.160.16'
let ip_filter = rawData => {
  let splitIp = ip.split('.')
  // console.log(
  //   'packet ip:' +
  //     rawData[12] +
  //     '.' +
  //     rawData[13] +
  //     '.' +
  //     rawData[14] +
  //     '.' +
  //     rawData[15]
  // )
  return (
    rawData[12] === parseInt(splitIp[0]) &&
    rawData[13] === parseInt(splitIp[1]) &&
    rawData[14] === parseInt(splitIp[2]) &&
    rawData[15] === parseInt(splitIp[3])
  )
}

let findEndPos = (all, start) => {
  let cursor = start
  while (cursor <= all.length) {
    if (
      (all[cursor] === 0x41 || all[cursor] === 0x00) &&
      all[cursor + 1] < 0x20
    ) {
      return cursor
    } else {
      cursor++
    }
  }
  return cursor
}

let outlandSrols = []

let combine = longRaw => {
  // console.log('combine 来了')
  // console.log(longRaw)
  let results = []
  let nicknameMatcher = 0
  let idMatcher = 0
  let nickname,
    ids = []
  let newOne = true

  let outlandScoreMathcher = 0,
    outlandScore // 外域评分outland_score

  longRaw.forEach((c, i, all) => {
    // console.log('我来了~~~~')
    if (newOne) {
      ids = []
    }
    if (c === 'rid'.charCodeAt(idMatcher)) {
      idMatcher++
      if ('rid'.length === idMatcher) {
        idMatcher = 0
        let start = i + 1 + 2
        let end = findEndPos(all, start)
        if (end !== -1) {
          let id = Buffer.from(all.slice(start, end)).toString()
          // console.log(id)
          ids.push(id)
        }
      }
    } else {
      idMatcher = 0
    }

    //外域分
    if (c === 'outland_score'.charCodeAt(outlandScoreMathcher)) {
      outlandScoreMathcher++
      if ('outland_score'.length === outlandScoreMathcher) {
        outlandScoreMathcher = 0
        let start = i + 1 + 1
        let end = findEndPos(all, start)
        if (end !== -1) {
          outlandScore = all.slice(start, end).reduce((a, c) => (a << 8) + c, 0)
          outlandSrols.push(outlandScore)
        }
      }
    } else {
      outlandScoreMathcher = 0
    }

    // var outlandObj = sysData(c,i,all,'outland_score', outlandScoreMathcher)
    // outlandScore = outlandObj.score
    // outlandScoreMathcher = outlandObj.matcher

    if (c === 'nickname'.charCodeAt(nicknameMatcher)) {
      nicknameMatcher++
      if ('nickname'.length === nicknameMatcher) {
        let start = i + 1 + 2 + ':b64:'.length
        let end = findEndPos(all, start)
        if (end !== -1) {
          nickname = Buffer.from(
            Buffer.from(all.slice(start, end)).toString(),
            'base64'
          ).toString()
          // console.log(nickname)
        }
        results.push({
          nickname,
          ids
        })

        newOne = true
        nicknameMatcher = 0
      }
    } else {
      nicknameMatcher = 0
      newOne = false
    }
  })
  // results.push({ nickname, ids })
  // console.log(nickname)
  // console.log(ids)
  console.log('------------------------------------')
  return results
}
let matcher = rawData => {
  let nicknameMatcher = 0
  let mopUpMatcher = 0
  let totalScoreMatcher = 0
  let idMatcher = 0
  let nickname,
    mopUp,
    ids = [],
    totalScore
  let fruitMatcher = 0,
    fruit
  let techSocoreMatcher = 0,
    techSocore // 科技分 eden_tech
  let maxExploreMatcher = 0,
    maxExplpreLebel // 天空爬高等级 max_explore_level
  let outlandProgressMathcher = 0,
    outlandProgress //外域完成度 outland_progress
  let outlandScore // 外域评分outland_score
  let edenIDMathcher = 0,
    edenID //伊甸id eden_id
  let dpMatcher = 0,
    dp
  rawData.forEach((c, i, all) => {
    if (c === 'nickname'.charCodeAt(nicknameMatcher)) {
      nicknameMatcher++
      if ('nickname'.length === nicknameMatcher) {
        nicknameMatcher = 0
        let start = i + 1 + 2 + ':b64:'.length
        let end = findEndPos(all, start)
        if (end !== -1) {
          nickname = Buffer.from(
            Buffer.from(all.slice(start, end)).toString(),
            'base64'
          ).toString()
        }
      }
    } else {
      nicknameMatcher = 0
    }
    if (c === 'mop_dungeon_times'.charCodeAt(mopUpMatcher)) {
      mopUpMatcher++
      if ('mop_dungeon_times'.length === mopUpMatcher) {
        mopUpMatcher = 0
        let start = i + 1 + 1
        let end = findEndPos(all, start)
        if (end !== -1) {
          mopUp = all.slice(start, end).reduce((a, c) => (a << 8) + c, 0)
        }
      }
    } else {
      mopUpMatcher = 0
    }

    //let techSocoreMatcher = 0, techSocore; // 科技分 eden_tech
    if (c === 'eden_tech'.charCodeAt(techSocoreMatcher)) {
      techSocoreMatcher++
      if ('eden_tech'.length === techSocoreMatcher) {
        techSocoreMatcher = 0
        let start = i + 1 + 1
        let end = findEndPos(all, start)
        if (end !== -1) {
          techSocore = all.slice(start, end).reduce((a, c) => (a << 8) + c, 0)
        }
      }
    } else {
      techSocoreMatcher = 0
    }

    //  let maxExploreMatcher = 0, maxExplpreLebel; // 天空爬高等级 max_explore_level
    if (c === 'max_explore_level'.charCodeAt(maxExploreMatcher)) {
      maxExploreMatcher++
      if ('max_explore_level'.length === maxExploreMatcher) {
        maxExploreMatcher = 0
        let start = i + 1 + 1
        let end = findEndPos(all, start)
        if (end !== -1) {
          maxExplpreLebel = all
            .slice(start, end)
            .reduce((a, c) => (a << 8) + c, 0)
        }
      }
    } else {
      maxExploreMatcher = 0
    }
    //   let outlandProgressMathcher = 0, outlandProgress   //外域完成度 outland_progress
    if (c === 'outland_progress'.charCodeAt(outlandProgressMathcher)) {
      outlandProgressMathcher++
      if ('outland_progress'.length === outlandProgressMathcher) {
        outlandProgressMathcher = 0
        let start = i + 1 + 1
        let end = findEndPos(all, start)
        if (end !== -1) {
          outlandProgress = all
            .slice(start, end)
            .reduce((a, c) => (a << 8) + c, 0)
        }
      }
    } else {
      outlandProgressMathcher = 0
    }
    if (c === 'rid'.charCodeAt(idMatcher)) {
      idMatcher++
      if ('rid'.length === idMatcher) {
        idMatcher = 0
        let start = i + 1 + 2
        let end = findEndPos(all, start)
        if (end !== -1) {
          let id = Buffer.from(all.slice(start, end)).toString()
          ids.push(id)
        }
      }
    } else {
      idMatcher = 0
    }
    if (c === 'overall_score'.charCodeAt(totalScoreMatcher)) {
      totalScoreMatcher++
      if ('overall_score'.length === totalScoreMatcher) {
        totalScoreMatcher = 0
        let start = i + 1 + 1
        let end = findEndPos(all, start)
        if (end !== -1) {
          totalScore = all.slice(start, end).reduce((a, c) => (a << 8) + c, 0)
        }
      }
    } else {
      totalScoreMatcher = 0
    }

    if (c === 'eden_id'.charCodeAt(edenIDMathcher)) {
      edenIDMathcher++
      if ('eden_id'.length === edenIDMathcher) {
        edenIDMathcher = 0
        let start = i + 1 + 1
        let end = findEndPos(all, start)
        if (end !== -1) {
          edenID = all.slice(start, end).reduce((a, c) => (a << 8) + c, 0)
        }
      }
    } else {
      edenIDMathcher = 0
    }

    if (c === 'fruit_num'.charCodeAt(fruitMatcher)) {
      fruitMatcher++
      if ('fruit_num'.length === fruitMatcher) {
        fruitMatcher = 0
        let start = i + 1 + 1
        let end = findEndPos(all, start)
        if (end !== -1) {
          fruit = all.slice(start, end).reduce((a, c) => (a << 8) + c, 0)
        }
      }
    } else {
      fruitMatcher = 0
    }
    if (c === 'dungeon_dp'.charCodeAt(dpMatcher)) {
      dpMatcher++
      if ('dungeon_dp'.length === dpMatcher) {
        dpMatcher = 0
        let start = i + 1 + 1
        let end = findEndPos(all, start)
        if (end !== -1) {
          dp = all.slice(start, end).reduce((a, c) => (a << 8) + c, 0)
        }
      }
    } else {
      dpMatcher = 0
    }
  })

  if (nickname || mopUp) {
    return {
      nickname,
      totalScore,
      mopUp,
      ids,
      fruit,
      dp,
      techSocore,
      maxExplpreLebel,
      outlandProgress,
      outlandScore,
      edenID
    }
  } else {
    return undefined
  }
}
let capData = []
let rs = []
process.stdin.pipe(pcapNgParser)
myFileStream
  .pipe(pcapNgParser)
  .on('data', parsedPacket => {
    let rawData = parsedPacket.data
    if (true || ip_filter(rawData)) {
      // console.log(rawData.length)
      if (rawData.length > 500) {
        //1500 自己的
        //1492
        let rest = rawData.slice(37, 1384) // 37 , 1489
        rest.forEach(a => capData.push(a))
        capData.push(rest)
        let result = matcher(rawData)
        if (result) {
          rs.push(result)
        }
      } else {
        let result = matcher(rawData)
        if (result) {
          rs.push(result)
        }
      }
    }
  })
  .on('interface', interfaceInfo => {})
let rrs = []

setTimeout(() => {
  let ns = combine(capData)
  // console.log(ns)

  let allNames = ns.reduce((arr, b) => {
    if (arr.indexOf(b['nickname']) === 1) {
      arr.push(b['nickname'])
    }
    if (arr.indexOf(b['outlandScore']) === 1) {
      arr.push(b['outlandScore'])
    }
    if (arr.indexOf(b['edenID']) === 1) {
      arr.push(b['edenID'])
    }
    return arr
  }, [])

  let idMap = {}
  let cnt = 0
  rs.forEach(r => {
    if (r['totalScore'] && r['mopUp']) {
      cnt++
      let found = ns.find(n => {
        for (let i in r['ids']) {
          if (n['ids'].indexOf(r['ids'][i]) !== -1) {
            return true
          }
        }
      })
      var nicknamed = '-1'
      var mopDiffer = -1
      dpsData.map(e => {
        // console.log(r['edenID'] + '------------------')
        if (r['edenID'] == e['edenID']) {
          //说明找到了
          mopDiffer = r['mopUp'] - e['mopUp']
          if (nicknamed == '-1') {
            console.log('找到了!!!' + e['nickName'] + e['edenID'])
            nicknamed = e['nickName']
          }
        }
      })

      if (found && nicknamed == '-1') {
        console.log('数据包名字' + found['nickname'])
        nicknamed = found['nickname']
      }

      rrs.push({
        nickname: nicknamed,
        totalScore: r['totalScore'],
        edenID: r['edenID'],
        // outlandScore: ourlandScrored,
        mopUp: r['mopUp'],
        mopDiffer: mopDiffer,
        fruit: r['fruit'],
        dp: r['dp'],
        id: r['ids'][0],
        outlandProgress: r['outlandProgress'],
        maxExplpreLebel: r['maxExplpreLebel'],
        techSocore: r['techSocore']
      })
    }
    if (r['nickname'] && r['totalScore'] && r['mopUp']) {
      rrs.push(r)
    }
  })
  rrs.sort((a, b) => b['totalScore'] - a['totalScore'])
  rrs = rrs.filter((r, i, a) => {
    return !a.slice(0, i).find(j => r['id'] === j['id'])
  })
  allNames.map(name => {
    // console.log('name---' + name)
    if (!rrs.find(r => r['nickname'] === name)) {
      rrs.push({
        nickname: name
      })
    }
  })
  console.log('-----------------------------------')

  // console.table(rrs)
  // console.log(JSON.stringify(rrs))

  //写文件操作
  var jsonstr = JSON.stringify(rrs)
  var json = JSON.parse(jsonstr)
  // console.log(json)
  var need_title = [
    'nickName',
    'edenID',
    '总分',
    'mopUp',
    '扫荡差',
    '果实数',
    'dp',
    'id',
    '外域进度',
    '最高层数',
    '科技分'
  ]
  var org_datas = [
    'nickname',
    'edenID',
    'totalScore',
    'mopUp',
    'mopDiffer',
    'fruit',
    'dp',
    'id',
    'outlandProgress',
    'maxExplpreLebel',
    'techSocore'
  ]

  var _data = json.map(e => {
    tmp = {}
    for (var i = 0; i < need_title.length; i++) {
      Object.assign(tmp, {
        [need_title[i]]: e[org_datas[i]]
      })
    }
    return tmp
  })

  // console.log(_data)

  var _headers = need_title
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
          {
            v: v[k],
            position: String.fromCharCode(65 + j) + (i + 2)
          }
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
}, 2000)
