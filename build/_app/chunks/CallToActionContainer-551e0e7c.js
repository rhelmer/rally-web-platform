import{S as t,i as e,s,M as n,E as a,e as o,c as l,a as r,d as c,b as i,Z as u,f as p,k as d,n as h,I as f,R as g,F as m,G as b,H as $,x as v,u as y,am as w,_ as E,A as I}from"./vendor-c0074b30.js";function S(t,e,s){const n=t.slice();return n[12]=e[s],n}function T(t){let e;return{c(){e=o("div"),this.h()},l(t){e=l(t,"DIV",{class:!0,style:!0}),r(e).forEach(c),this.h()},h(){i(e,"class","onboarding-cta-step svelte-127u3nb"),u(e,"opacity",t[12]+1===t[0]?"1":".25")},m(t,s){p(t,e,s)},p(t,s){3&s&&u(e,"opacity",t[12]+1===t[0]?"1":".25")},d(t){t&&c(e)}}}function D(t){let e,s,u,I,D,k,x,A,H=!1,O=()=>{H=!1};n(t[10]),n(t[11]);const R=t[9].default,z=a(R,t,t[8],null);let M=Array.from({length:t[1]}).map(V),j=[];for(let n=0;n<M.length;n+=1)j[n]=T(S(t,M,n));return{c(){s=o("div"),u=o("div"),z&&z.c(),I=d(),D=o("div");for(let t=0;t<j.length;t+=1)j[t].c();this.h()},l(t){s=l(t,"DIV",{class:!0,style:!0});var e=r(s);u=l(e,"DIV",{class:!0});var n=r(u);z&&z.l(n),n.forEach(c),I=h(e),D=l(e,"DIV",{class:!0});var a=r(D);for(let s=0;s<j.length;s+=1)j[s].l(a);a.forEach(c),e.forEach(c),this.h()},h(){i(u,"class","onboarding-cta-inner svelte-127u3nb"),i(D,"class","onboarding-cta-steps svelte-127u3nb"),i(s,"class","onboarding-cta-container svelte-127u3nb"),i(s,"style",t[4])},m(n,a){p(n,s,a),f(s,u),z&&z.m(u,null),f(s,I),f(s,D);for(let t=0;t<j.length;t+=1)j[t].m(D,null);k=!0,x||(A=[g(window,"scroll",(()=>{H=!0,clearTimeout(e),e=setTimeout(O,100),t[10]()})),g(window,"resize",t[11])],x=!0)},p(t,[n]){if(4&n&&!H&&(H=!0,clearTimeout(e),scrollTo(window.pageXOffset,t[2]),e=setTimeout(O,100)),z&&z.p&&(!k||256&n)&&m(z,R,t,t[8],k?$(R,t[8],n,null):b(t[8]),null),3&n){let e;for(M=Array.from({length:t[1]}).map(V),e=0;e<M.length;e+=1){const s=S(t,M,e);j[e]?j[e].p(s,n):(j[e]=T(s),j[e].c(),j[e].m(D,null))}for(;e<j.length;e+=1)j[e].d(1);j.length=M.length}(!k||16&n)&&i(s,"style",t[4])},i(t){k||(v(z,t),k=!0)},o(t){y(z,t),k=!1},d(t){t&&c(s),z&&z.d(t),w(j,t),x=!1,E(A)}}}const V=(t,e)=>e;function k(t,e,s){let n,a,{$$slots:o={},$$scope:l}=e,{step:r=1}=e,{totalSteps:c=3}=e,{transparent:i=!1}=e,u=0,p=0,d=0;return I((()=>{s(6,d=document.body.clientHeight);new ResizeObserver((([t])=>{s(6,d=t.contentRect.height)})).observe(document.body)})),t.$$set=t=>{"step"in t&&s(0,r=t.step),"totalSteps"in t&&s(1,c=t.totalSteps),"transparent"in t&&s(5,i=t.transparent),"$$scope"in t&&s(8,l=t.$$scope)},t.$$.update=()=>{76&t.$$.dirty&&s(7,n=Math.min(1,(d-(u+p))/130)),160&t.$$.dirty&&s(4,a=i?"--background: none":`\n--background: linear-gradient(\n    to bottom,\n    transparent 0%,\n    rgba(249, 249, 251, ${n}) 45%\n  );\n`)},[r,c,u,p,a,i,d,n,l,o,function(){s(2,u=window.pageYOffset)},function(){s(3,p=window.innerHeight)}]}class x extends t{constructor(t){super(),e(this,t,k,D,s,{step:0,totalSteps:1,transparent:5})}}export{x as C};