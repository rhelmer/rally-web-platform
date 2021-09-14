import{S as e,i as t,s as l,X as s,Y as a,a as n,d as r,b as i,f as o,I as c,P as u,e as h,j as d,t as f,c as p,m,g as v,o as g,R as y,x as b,M as w,V as $,O as k,u as E,v as _,a1 as x,E as z,k as R,n as I,Q as N,Z as P,h as T,r as V,w as A,F as O,G as j,H as D,N as L,am as M,an as U,l as q,a2 as B,ao as S,_ as C}from"./vendor-9977621c.js";import{s as F,q as H,c as Y,a as G,i as Q,b as X,d as Z}from"./survey-schema-481feb4b.js";function J(e){let t,l;return{c(){t=s("svg"),l=s("path"),this.h()},l(e){t=a(e,"svg",{xmlns:!0,width:!0,height:!0,viewBox:!0});var s=n(t);l=a(s,"path",{fill:!0,d:!0}),n(l).forEach(r),s.forEach(r),this.h()},h(){i(l,"fill",e[1]),i(l,"d","M9.061 8l3.47-3.47a.75.75 0 0 0-1.061-1.06L8 6.939 4.53 3.47a.75.75 0 1\n    0-1.06 1.06L6.939 8 3.47 11.47a.75.75 0 1 0 1.06 1.06L8 9.061l3.47\n    3.47a.75.75 0 0 0 1.06-1.061z"),i(t,"xmlns","http://www.w3.org/2000/svg"),i(t,"width",e[0]),i(t,"height",e[0]),i(t,"viewBox","0 0 16 16")},m(e,s){o(e,t,s),c(t,l)},p(e,[s]){2&s&&i(l,"fill",e[1]),1&s&&i(t,"width",e[0]),1&s&&i(t,"height",e[0])},i:u,o:u,d(e){e&&r(t)}}}function K(e,t,l){let{size:s="1em"}=t,{color:a="currentColor"}=t;return e.$$set=e=>{"size"in e&&l(0,s=e.size),"color"in e&&l(1,a=e.color)},[s,a]}class W extends e{constructor(e){super(),t(this,e,K,J,l,{size:0,color:1})}}function ee(e){let t,l,s,a,x,z,R;return l=new W({}),{c(){t=h("button"),d(l.$$.fragment),s=f(" Clear this response"),this.h()},l(e){t=p(e,"BUTTON",{class:!0});var a=n(t);m(l.$$.fragment,a),s=v(a," Clear this response"),a.forEach(r),this.h()},h(){i(t,"class","gafc mzp-t-sm mzp-c-button mzp-t-neutral mzp-t-product svelte-1f55xcj")},m(a,n){o(a,t,n),g(l,t,null),c(t,s),x=!0,z||(R=y(t,"click",e[0]),z=!0)},p:u,i(e){x||(b(l.$$.fragment,e),e&&w((()=>{a||(a=$(t,k,{duration:150,y:2.5},!0)),a.run(1)})),x=!0)},o(e){E(l.$$.fragment,e),e&&(a||(a=$(t,k,{duration:150,y:2.5},!1)),a.run(0)),x=!1},d(e){e&&r(t),_(l),e&&a&&a.end(),z=!1,R()}}}function te(e){return[function(t){x.call(this,e,t)}]}class le extends e{constructor(e){super(),t(this,e,te,ee,l,{})}}const se=e=>({formattedResults:1&e,validated:1&e}),ae=e=>({formattedResults:G(F,e[0],Q),validated:Q.validateAllQuestions(F,e[0])});function ne(e,t,l){const s=e.slice();return s[12]=t[l],s[13]=t,s[14]=l,s}function re(e,t,l){const s=e.slice();return s[15]=t[l],s}const ie=e=>({}),oe=e=>({}),ce=e=>({}),ue=e=>({});function he(e){let t,l;return t=new le({}),t.$on("click",(function(...t){return e[5](e[12],...t)})),{c(){d(t.$$.fragment)},l(e){m(t.$$.fragment,e)},m(e,s){g(t,e,s),l=!0},p(t,l){e=t},i(e){l||(b(t.$$.fragment,e),l=!0)},o(e){E(t.$$.fragment,e),l=!1},d(e){_(t,e)}}}function de(e){let t,l,s=F[e[12]].sublabel+"";return{c(){t=h("div"),l=f(s),this.h()},l(e){t=p(e,"DIV",{style:!0});var a=n(t);l=v(a,s),a.forEach(r),this.h()},h(){P(t,"padding-top","-8px"),P(t,"padding-bottom","20px")},m(e,s){o(e,t,s),c(t,l)},p(e,t){1&t&&s!==(s=F[e[12]].sublabel+"")&&T(l,s)},d(e){e&&r(t)}}}function fe(e){let t,l=F[e[12]].values,s=[];for(let a=0;a<l.length;a+=1)s[a]=ge(re(e,l,a));return{c(){for(let e=0;e<s.length;e+=1)s[e].c();t=q()},l(e){for(let t=0;t<s.length;t+=1)s[t].l(e);t=q()},m(e,l){for(let t=0;t<s.length;t+=1)s[t].m(e,l);o(e,t,l)},p(e,a){if(1&a){let n;for(l=F[e[12]].values,n=0;n<l.length;n+=1){const r=re(e,l,n);s[n]?s[n].p(r,a):(s[n]=ge(r),s[n].c(),s[n].m(t.parentNode,t))}for(;n<s.length;n+=1)s[n].d(1);s.length=l.length}},d(e){M(s,e),e&&r(t)}}}function pe(e){let t,l,s,a,u,d,f,m,v=Q.showErrors(e[12])&&Q.hasValidator(e[12])&&Q[e[12]].isInvalid(e[0][e[12]]);function g(...t){return e[6](e[12],...t)}function w(...t){return e[7](e[12],...t)}function $(...t){return e[8](e[12],...t)}let k=v&&ye(e);return{c(){t=h("div"),l=h("input"),u=R(),d=h("span"),k&&k.c(),this.h()},l(e){t=p(e,"DIV",{class:!0});var s=n(t);l=p(s,"INPUT",{type:!0,class:!0}),u=I(s),d=p(s,"SPAN",{style:!0});var a=n(d);k&&k.l(a),a.forEach(r),s.forEach(r),this.h()},h(){i(l,"type","text"),l.value=s=e[0][e[12]],i(l,"class","svelte-egpre2"),N(l,"right",Q[e[12]].alignRight),P(d,"min-height","24px"),P(d,"display","block"),i(t,"class","mzp-c-choice mzp-c-choice-text svelte-egpre2"),N(t,"mzp-is-error",Q.showErrors(e[12])&&Q.hasValidator(e[12])&&Q[e[12]].isInvalid(e[0][e[12]]))},m(s,n){o(s,t,n),c(t,l),c(t,u),c(t,d),k&&k.m(d,null),f||(m=[B(a=Z.call(null,l,Q[e[12]])),y(l,"blur",g),y(l,"focus",w),y(l,"input",$)],f=!0)},p(n,r){e=n,1&r&&s!==(s=e[0][e[12]])&&l.value!==s&&(l.value=s),a&&S(a.update)&&1&r&&a.update.call(null,Q[e[12]]),1&r&&N(l,"right",Q[e[12]].alignRight),1&r&&(v=Q.showErrors(e[12])&&Q.hasValidator(e[12])&&Q[e[12]].isInvalid(e[0][e[12]])),v?k?(k.p(e,r),1&r&&b(k,1)):(k=ye(e),k.c(),b(k,1),k.m(d,null)):k&&(V(),E(k,1,1,(()=>{k=null})),A()),1&r&&N(t,"mzp-is-error",Q.showErrors(e[12])&&Q.hasValidator(e[12])&&Q[e[12]].isInvalid(e[0][e[12]]))},d(e){e&&r(t),k&&k.d(),f=!1,C(m)}}}function me(e){let t,l,s,a,n;function c(){e[11].call(t,e[12],e[14])}return e[10][0][e[14]]=[],{c(){t=h("input"),this.h()},l(e){t=p(e,"INPUT",{class:!0,type:!0,id:!0}),this.h()},h(){i(t,"class","mzp-c-choice-control svelte-egpre2"),i(t,"type","checkbox"),i(t,"id",l="answer-"+e[15].key),t.__value=s=e[15].key,t.value=t.__value,e[10][0][e[14]].push(t)},m(l,s){o(l,t,s),t.checked=~e[0][e[12]].indexOf(t.__value),a||(n=y(t,"change",c),a=!0)},p(a,n){e=a,1&n&&l!==(l="answer-"+e[15].key)&&i(t,"id",l),1&n&&s!==(s=e[15].key)&&(t.__value=s,t.value=t.__value),1&n&&(t.checked=~e[0][e[12]].indexOf(t.__value))},d(l){l&&r(t),e[10][0][e[14]].splice(e[10][0][e[14]].indexOf(t),1),a=!1,n()}}}function ve(e){let t,l,s,a,n;function c(){e[9].call(t,e[12])}return e[10][0][e[14]]=[],{c(){t=h("input"),this.h()},l(e){t=p(e,"INPUT",{class:!0,type:!0,id:!0}),this.h()},h(){i(t,"class","mzp-c-choice-control svelte-egpre2"),i(t,"type","radio"),i(t,"id",l="answer-"+e[15].key),t.__value=s=e[15].key,t.value=t.__value,e[10][0][e[14]].push(t)},m(l,s){o(l,t,s),t.checked=t.__value===e[0][e[12]],a||(n=y(t,"change",c),a=!0)},p(a,n){e=a,1&n&&l!==(l="answer-"+e[15].key)&&i(t,"id",l),1&n&&s!==(s=e[15].key)&&(t.__value=s,t.value=t.__value),1&n&&(t.checked=t.__value===e[0][e[12]])},d(l){l&&r(t),e[10][0][e[14]].splice(e[10][0][e[14]].indexOf(t),1),a=!1,n()}}}function ge(e){let t,l,s,a,u,d,m=e[15].label+"";function g(e,t){return"single"===F[e[12]].type?ve:"multi"===F[e[12]].type?me:void 0}let y=g(e),b=y&&y(e);return{c(){t=h("div"),b&&b.c(),l=R(),s=h("label"),a=f(m),d=R(),this.h()},l(e){t=p(e,"DIV",{class:!0});var i=n(t);b&&b.l(i),l=I(i),s=p(i,"LABEL",{class:!0,for:!0});var o=n(s);a=v(o,m),o.forEach(r),d=I(i),i.forEach(r),this.h()},h(){i(s,"class","mzp-c-choice-label svelte-egpre2"),i(s,"for",u="answer-"+e[15].key),i(t,"class","mzp-c-choice svelte-egpre2")},m(e,n){o(e,t,n),b&&b.m(t,null),c(t,l),c(t,s),c(s,a),c(t,d)},p(e,n){y===(y=g(e))&&b?b.p(e,n):(b&&b.d(1),b=y&&y(e),b&&(b.c(),b.m(t,l))),1&n&&m!==(m=e[15].label+"")&&T(a,m),1&n&&u!==(u="answer-"+e[15].key)&&i(s,"for",u)},d(e){e&&r(t),b&&b.d()}}}function ye(e){let t,l,s,a,u=Q[e[12]].isInvalid(e[0][e[12]])+"";return{c(){t=h("span"),l=f(u),this.h()},l(e){t=p(e,"SPAN",{class:!0});var s=n(t);l=v(s,u),s.forEach(r),this.h()},h(){i(t,"class","mzp-c-fieldnote")},m(e,s){o(e,t,s),c(t,l),a=!0},p(e,t){(!a||1&t)&&u!==(u=Q[e[12]].isInvalid(e[0][e[12]])+"")&&T(l,u)},i(e){a||(e&&w((()=>{s||(s=$(t,k,{duration:300,y:5},!0)),s.run(1)})),a=!0)},o(e){e&&(s||(s=$(t,k,{duration:300,y:5},!1)),s.run(0)),a=!1},d(e){e&&r(t),e&&s&&s.end()}}}function be(e){let t,l,s,a,u,d,m,g,y,w,$=F[e[12]].label+"",k=H(e[0][e[12]],F[e[12]].type),_=k&&he(e),x=F[e[12]].sublabel&&de(e);function z(e,t){return"text"===F[e[12]].type?pe:fe}let O=z(e),j=O(e);return{c(){t=h("fieldset"),l=h("legend"),s=f($),a=R(),_&&_.c(),d=R(),x&&x.c(),m=R(),g=h("div"),j.c(),y=R(),this.h()},l(e){t=p(e,"FIELDSET",{class:!0});var i=n(t);l=p(i,"LEGEND",{class:!0,for:!0});var o=n(l);s=v(o,$),a=I(o),_&&_.l(o),o.forEach(r),d=I(i),x&&x.l(i),m=I(i),g=p(i,"DIV",{class:!0,style:!0});var c=n(g);j.l(c),c.forEach(r),y=I(i),i.forEach(r),this.h()},h(){i(l,"class","mzp-c-field-label svelte-egpre2"),i(l,"for",u=F[e[12]].key),N(l,"remove-bottom-margin",F[e[12]].sublabel),i(g,"class","mzp-c-choices svelte-egpre2"),P(g,"--rows",F[e[12]].values?Math.ceil(F[e[12]].values.length/2):0),N(g,"two-columns",F[e[12]].columns),i(t,"class","mzp-c-field-set svelte-egpre2"),N(t,"mzp-c-field-set-text","text"===F[e[12]].type)},m(e,n){o(e,t,n),c(t,l),c(l,s),c(l,a),_&&_.m(l,null),c(t,d),x&&x.m(t,null),c(t,m),c(t,g),j.m(g,null),c(t,y),w=!0},p(e,a){(!w||1&a)&&$!==($=F[e[12]].label+"")&&T(s,$),1&a&&(k=H(e[0][e[12]],F[e[12]].type)),k?_?(_.p(e,a),1&a&&b(_,1)):(_=he(e),_.c(),b(_,1),_.m(l,null)):_&&(V(),E(_,1,1,(()=>{_=null})),A()),(!w||1&a&&u!==(u=F[e[12]].key))&&i(l,"for",u),1&a&&N(l,"remove-bottom-margin",F[e[12]].sublabel),F[e[12]].sublabel?x?x.p(e,a):(x=de(e),x.c(),x.m(t,m)):x&&(x.d(1),x=null),O===(O=z(e))&&j?j.p(e,a):(j.d(1),j=O(e),j&&(j.c(),j.m(g,null))),(!w||1&a)&&P(g,"--rows",F[e[12]].values?Math.ceil(F[e[12]].values.length/2):0),1&a&&N(g,"two-columns",F[e[12]].columns),1&a&&N(t,"mzp-c-field-set-text","text"===F[e[12]].type)},i(e){w||(b(_),w=!0)},o(e){E(_),w=!1},d(e){e&&r(t),_&&_.d(),x&&x.d(),j.d()}}}function we(e){let t,l,s,a,u,d,m,g,y,$;const _=e[4].title,x=z(_,e,e[3],ue),N=x||function(e){let t,l;return{c(){t=h("span"),l=f("Tell Us About Yourself")},l(e){t=p(e,"SPAN",{});var s=n(t);l=v(s,"Tell Us About Yourself"),s.forEach(r)},m(e,s){o(e,t,s),c(t,l)},d(e){e&&r(t)}}}(),P=e[4].description,T=z(P,e,e[3],oe),U=T||function(e){let t,l;return{c(){t=h("p"),l=f("Each question is completely optional, and can be updated at any time by clicking Manage Profile. \n      The answers you give will help us understand the composition and representivity of the Rally community.\n      Additionally, collaborators will combine your answers with the data collected in the studies you join to enrich their findings and answer research questions.")},l(e){t=p(e,"P",{});var s=n(t);l=v(s,"Each question is completely optional, and can be updated at any time by clicking Manage Profile. \n      The answers you give will help us understand the composition and representivity of the Rally community.\n      Additionally, collaborators will combine your answers with the data collected in the studies you join to enrich their findings and answer research questions."),s.forEach(r)},m(e,s){o(e,t,s),c(t,l)},d(e){e&&r(t)}}}();let q=Object.keys(e[0]),B=[];for(let n=0;n<q.length;n+=1)B[n]=be(ne(e,q,n));const S=e=>E(B[e],1,1,(()=>{B[e]=null})),C=e[4]["call-to-action"],F=z(C,e,e[3],ae);return{c(){t=h("div"),l=h("h2"),N&&N.c(),s=R(),U&&U.c(),a=R(),u=h("hr"),d=R(),m=h("form");for(let e=0;e<B.length;e+=1)B[e].c();g=R(),F&&F.c(),this.h()},l(e){t=p(e,"DIV",{});var i=n(t);l=p(i,"H2",{class:!0});var o=n(l);N&&N.l(o),o.forEach(r),s=I(i),U&&U.l(i),a=I(i),u=p(i,"HR",{}),d=I(i),m=p(i,"FORM",{class:!0});var c=n(m);for(let t=0;t<B.length;t+=1)B[t].l(c);c.forEach(r),g=I(i),F&&F.l(i),i.forEach(r),this.h()},h(){i(l,"class","section-header"),i(m,"class","mzp-c-form")},m(e,n){o(e,t,n),c(t,l),N&&N.m(l,null),c(t,s),U&&U.m(t,null),c(t,a),c(t,u),c(t,d),c(t,m);for(let t=0;t<B.length;t+=1)B[t].m(m,null);c(t,g),F&&F.m(t,null),$=!0},p(e,[t]){if(x&&x.p&&(!$||8&t)&&O(x,_,e,e[3],$?D(_,e[3],t,ce):j(e[3]),ue),T&&T.p&&(!$||8&t)&&O(T,P,e,e[3],$?D(P,e[3],t,ie):j(e[3]),oe),1&t){let l;for(q=Object.keys(e[0]),l=0;l<q.length;l+=1){const s=ne(e,q,l);B[l]?(B[l].p(s,t),b(B[l],1)):(B[l]=be(s),B[l].c(),b(B[l],1),B[l].m(m,null))}for(V(),l=q.length;l<B.length;l+=1)S(l);A()}F&&F.p&&(!$||9&t)&&O(F,C,e,e[3],$?D(C,e[3],t,se):j(e[3]),ae)},i(e){if(!$){b(N,e),b(U,e);for(let e=0;e<q.length;e+=1)b(B[e]);b(F,e),e&&(y||w((()=>{y=L(t,k,{duration:800,y:5}),y.start()}))),$=!0}},o(e){E(N,e),E(U,e),B=B.filter(Boolean);for(let t=0;t<B.length;t+=1)E(B[t]);E(F,e),$=!1},d(e){e&&r(t),N&&N.d(e),U&&U.d(e),M(B,e),F&&F.d(e)}}}function $e(e,t,l){let{$$slots:s={},$$scope:a}=t,{results:n=Y(F)}=t,{workingResults:r=Y(F,n)}=t,{formattedResults:i=G(F,r,Q)}=t;const o=[[]];return e.$$set=e=>{"results"in e&&l(2,n=e.results),"workingResults"in e&&l(0,r=e.workingResults),"formattedResults"in e&&l(1,i=e.formattedResults),"$$scope"in e&&l(3,a=e.$$scope)},e.$$.update=()=>{1&e.$$.dirty&&l(0,r=Y(F,r)),1&e.$$.dirty&&l(1,i=G(F,r,Q))},[r,i,n,a,s,(e,t)=>{t.preventDefault(),l(0,r[e]=X(F[e].type),r)},(e,t)=>{l(0,r[e]=t.target.value,r)},(e,t)=>{l(0,r[e]=t.target.value,r)},(e,t)=>{l(0,r[e]=t.target.value,r)},function(e){r[e]=this.__value,l(0,r)},o,function(e,t){r[e]=U(o[0][t],this.__value,this.checked),l(0,r)}]}class ke extends e{constructor(e){super(),t(this,e,$e,we,l,{results:2,workingResults:0,formattedResults:1})}}export{ke as C};
