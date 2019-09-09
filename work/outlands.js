XLSX = require('xlsx')
namesJson = require('./jsons/allNames.json')
const PCAPNGParser = require('pcap-ng-parser')
const pcapNgParser = new PCAPNGParser()
const myFileStream = require('fs').createReadStream('./pcapng/test.pcapng')

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

let matcher = rawData => {
  let nicknameMatcher = 0
  let name

  let idMatcher = 0
  let rid

  let scoreMather = 0
  let score

  rawData.forEach((c, i, all) => {
    if (c === 'name'.charCodeAt(nicknameMatcher)) {
      nicknameMatcher++
      if ('name'.length === nicknameMatcher) {
        nicknameMatcher = 0
        let start = i + 1 + 2 + ':b64:'.length
        let end = findEndPos(all, start)
        if (end !== -1) {
          name = Buffer.from(
            Buffer.from(all.slice(start, end)).toString(),
            'base64'
          ).toString()
        }
      }
    } else {
      nicknameMatcher = 0
    }

    if (c === 'score'.charCodeAt(scoreMather)) {
      scoreMather++
      if ('score'.length === scoreMather) {
        scoreMather = 0
        let start = i + 1 + 1
        let end = findEndPos(all, start)
        if (end !== -1) {
          score = all.slice(start, end).reduce((a, c) => (a << 8) + c, 0)
        }
      }
    } else {
      scoreMather = 0
    }
    if (c === 'rid'.charCodeAt(idMatcher)) {
      idMatcher++
      if ('rid'.length === idMatcher) {
        idMatcher = 0
        let start = i + 1 + 2
        let end = findEndPos(all, start)
        if (end !== -1) {
          rid = Buffer.from(all.slice(start, end)).toString()
        }
      }
    } else {
      idMatcher = 0
    }
  })

  return {
    name,
    rid,
    score
  }
}
let capData = []
let rs = []
process.stdin.pipe(pcapNgParser)
myFileStream
  .pipe(pcapNgParser)
  .on('data', parsedPacket => {
    let rawData = parsedPacket.data
    let result = matcher(rawData)
    if (result) {
      rs.push(result)
    }
  })
  .on('interface', interfaceInfo => {})
let rrs = []

setTimeout(() => {
  rs.forEach(r => {
    console.log(r)

    rrs.push({
      name: r['name'],
      score: r['score'],
      rid: r['rid']
    })

    rrs.push(r)
  })
  rrs.sort((a, b) => b['score'] - a['score'])
  rrs = rrs.filter((r, i, a) => {
    return !a.slice(0, i).find(j => r['rid'] === j['rid'])
  })
  console.log('-----------------------------------')
  console.table(rrs)
}, 2000)
