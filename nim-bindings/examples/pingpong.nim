import results

import ../src/libchat

proc pingpong() =

  var raya = newConversationsContext()
  var saro = newConversationsContext()


  # Perform out of band Introduction
  let intro = raya.createIntroductionBundle().expect("[Raya] Couldn't create intro bundle")
  echo "Raya's Intro Bundle: ",intro

  var (convo_sr, payload) = saro.createNewPrivateConvo(intro,"Hey Raya").expect("[Saro] Couldn't create convo")
  echo "ConvoHandle::  ", convo_sr
  echo "Payload::      ", payload
  


when isMainModule:
  pingpong()
