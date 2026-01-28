import options
import results

import ../src/libchat

proc pingpong() =

  var raya = newConversationsContext()
  var saro = newConversationsContext()


  # Perform out of band Introduction
  let intro = raya.createIntroductionBundle().expect("[Raya] Couldn't create intro bundle")
  echo "Raya's Intro Bundle: ",intro

  var (convo_sr, payloads) = saro.createNewPrivateConvo(intro, "Hey Raya").expect("[Saro] Couldn't create convo")
  echo "ConvoHandle::  ", convo_sr
  echo "Payload::      ", payloads

  ## Send Payloads to Raya
  for p in payloads:
    let res = raya.handlePayload(p.data)
    if res.isOk:
      let opt = res.get()
      if opt.isSome:
        let content_result = opt.get()
        echo "RecvContent: ", content_result.conversationId, " ", content_result.data
    else:
      echo "Failed to handle payload: ", res.error

  echo "Done"

when isMainModule:
  pingpong()

