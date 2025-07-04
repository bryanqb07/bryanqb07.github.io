---
layout: post
title: "OSWE"
category: exam
tags: [oswe, oscp, exam]
---

<style>
/* More vertical spacing between sections */
h3 {
  margin-top: 30px;
}


/* Add spacing between paragraphs */
p {
  margin-bottom: 1.25em;
  line-height: 1.7;
}

/* Add breathing room around lists */
ul, ol {
  margin-bottom: 1.5em;
}

</style>

## Day 1

### 5 a.m.

Wake up due to sleep anxiety. It always happens to me the night before a big exam. I couldn’t stop thinking about the Extra Mile exercise for the Pug Prototype Pollution. While looking through the source code I thought I discovered an XSS vulnerability that hasn’t been uncovered yet. After looking into it for about an hour or so I decide to give it a break; I’ll need my brain for the exam later today.

### 10 a.m.

Started the exam 10 minutes late. I foolishly was waiting for the email to the proctoring link, but didn’t realize it had been sent the night before. Luckily I was able to connect without any issue.

The problems don’t stop here. For the first app I couldn’t quite figure out how to connect to the debugger. It takes me an hour or so before I can get it working. Even afterwards, I could only pause at breakpoints but couldn’t execute code in the debug console. While this didn’t end up making a difference it was an added obstacle.

The apps are actually smaller than I imagined. Coming from a SWE background I’m used to codebases 10x this size. Given that I solved all the challenge labs fairly smoothly I’m pretty confident about passing the exam.

I get started on app #1.

### 1 p.m.

Eat a small lunch.

### 2 p.m.

Brain is feeling a bit groggy due to lack of sleep. Been going through the source code for about 4 hours, yet still haven’t found anything promising. I’ve found a couple small vulnerabilities but none are able to lead to bypass.

Given how small the apps are, I’ve decided to go through every route one by one and every function to manually review them. Hopefully I will come across something.

### 5 p.m.

Went down a few rabbit holes but nothing promising. Deciding to switch to the other app to see if I have any better luck. Luckily the debug setup for this one is much easier.

### 9 p.m.

Brain is really tired at this point. Haven’t had any better luck in this app either. Just like the first app, there are some small vulnerabilities but I can’t exploit them in any meaningful way. I was hoping to get RCE on at least one box the first day to make the next day easier for me.

### 10:30 p.m.

Finally decide it’s time to take a break and eat dinner. My wife comes into the kitchen around this point. I tell her that there’s a high probability of me failing the exam. I can’t really believe this after I did so well in the challenge labs.

### 11 p.m.

Decide to switch back to the first app. I have a much better feel for that one. I see a path to RCE that I can likely get post-admin bypass, but I’ve had no luck trying to get admin creds. I decide to narrow in on the endpoint that I feel is most likely to give me access, but it has multiple filters so strict that I just can’t get through.

<br>

## Day 2

### 1 a.m.

Decide to call it a night and get some rest. It’s hard to do because my adrenaline is running so high. It’s a great feeling for me, even if I’m not doing so well at the moment.

As I lie in bed, I think about how the endpoint I’ve been trying to exploit reminds me of a PortSwigger lab that I did once, except that lab was much easier. Suddenly, an idea pops into my head for a solution, at least to get past the first filter. I jump out of bed and reconnect to the proctoring session.

I send my payload to the endpoint, expecting it to pass the first filter but not the next. To my surprise it goes through both and I get admin credentials! After re-reading the code, it turns out that I had overlooked a small detail that would allow my exploit to go through. Guess it never hurts to try things, even when in doubt!

From here, I have a decent idea of how to get code execution, it’s all just a matter of scripting it all out.

### 4 a.m.

Got RCE on the first box. Did most of this via code so my PoC script is about 70% done. I feel both exhilarated and exhausted. Time to get a little sleep.

### 7 a.m.

Wake up from my sleep. Not sure if it’s the anxiety or my kids that woke me up. Either way, I feel decently refreshed and optimistic about today. All I need is to find the auth bypass on app #2 and I’ve passed the exam. Given that I still have over a day remaining I feel confident about this.

### 9 a.m.

Still no luck. That said, when I first started this box I ruled out the possibility of a certain type of exploit. I’m going to revisit that assumption, even though it seems unlikely.

### 10 a.m.

Turns out the exploit I ruled out was exactly what was required to get auth bypass! I’ve now accessed the admin panel on the second app, which means the exam is passed. I go eat breakfast to celebrate.

### 11 a.m. – 9 p.m.

From here, I decide to go the conservative route and spend the rest of the day writing the PoC code as well as the exam report. If there’s time left over I’ll attempt to get RCE on the second app.

### 9 p.m.

Done with the report. Tested the PoCs multiple times. Both work fine. A bit worried about how the PDF document is going to affect the formatting of my Python script, but other than that I think it’s good to go.

I decide to attempt to find RCE on the second app. The possible exploit vectors for this are much smaller so I don’t think it should be too difficult.

### 11 p.m.

RCE proving to be more difficult than I thought.

<br>

## Day 3

### 1 a.m.

Found a way to get interaction from the server to my Kali machine! RCE seems to be in sight, just need to figure out the proper payload.

### 4 a.m.

After trying different combinations of payloads there’s still no luck. Brain is completely exhausted. Going to lie down.

### 9 a.m.

Woke up a lot later than I wanted to. Don’t have much time left.

Make a few more attempts at getting RCE. Found a different payload route that seems promising.

### 9:45 a.m.

Unfortunately time runs out before I can arrive at RCE. That’s okay though; I still have enough points to pass.

### 10 a.m.

Submit the exam report. Still a little nervous about the formatting of my code but I guess we’ll just have to wait and see.

<br>
## Final Thoughts

Overall I felt like it was an extremely fun exam, although it was much more difficult than I anticipated. I feel that I learned a lot during the course of the exam and honestly wish that I could take this multiple times to improve my skills. Also, there’s nothing more fulfilling than that moment when all the dots connect.


## Update

Got an email from OffSec the day after I submitted my exam report informing me that I have **passed**!
<br>
<br>
![OSWE](/assets/img/oswe/oswe.png)
