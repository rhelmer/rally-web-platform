import{S as s,i as t,s as e,D as i,J as n}from"../chunks/vendor-c0074b30.js";import{g as o}from"../chunks/navigation-2ffed81e.js";import"../chunks/singletons-12a22614.js";function r(s,t,e){let r,a;var l;const u=i("rally:store");n(s,u,(s=>e(3,r=s)));const d=i("rally:isAuthenticated");return n(s,d,(s=>e(4,a=s))),s.$$.update=()=>{28&s.$$.dirty&&void 0!==a&&r._initialized&&(!1===a?o("/signup"):(null===e(2,l=null==r?void 0:r.user)||void 0===l?void 0:l.enrolled)?o("/studies"):o("/welcome/terms"))},[u,d,l,r,a]}class a extends s{constructor(s){super(),t(this,s,r,null,e,{})}}export{a as default};