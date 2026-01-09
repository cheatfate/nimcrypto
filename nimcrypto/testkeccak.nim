import keccak/keccak

when isMainModule:
  var ctx: keccak256
  ctx.init()
  ctx.update("")
  echo ctx.finish()
