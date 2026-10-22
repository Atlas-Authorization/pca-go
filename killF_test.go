package pca

import (
	"strings"
	"testing"
)

// Kill tests for predicates.go (the Intent Layer v2 predicate DSL). The expected verdicts are produced by the TS
// reference (packages/pca/src/predicates.ts evaluateConditionTri / predicateMatches / evaluatePredicates) over the
// cartesian products described in killFLeafSpec: one character per case, 't' / 'f' / 'u' (tri-valued) or '1' / '0'.

const killFLeafSpec = `{"ctxText":"{\"action\":{\"verb\":\"read\",\"resource\":\"/acct/1/items/2\",\"params\":{\"amount\":5,\"amt2\":5.0,\"name\":\"alice\",\"tags\":[\"a\",\"b\"],\"nested\":{\"x\":[10,20,{\"y\":\"z\"}]},\"s\":\"héllo\",\"astral\":\"𐀀\",\"bmp\":\"￿\",\"lone\":\"\\ud800\",\"lone2\":\"\\udc00x\",\"nul\":null,\"zero\":0,\"negz\":-0,\"neg\":-1,\"inf\":1e400,\"t\":true,\"f\":false,\"doc\":{\"type\":\"doc::pdf\",\"tags\":[\"secret\",\"x\"]},\"objNoType\":{\"x\":1},\"objBadType\":{\"type\":5},\"objTagsNotArr\":{\"tags\":\"x\"},\"typeOnly\":{\"type\":\"doc\"},\"typeDoc2\":{\"type\":\"docx\"},\"tagsOnly\":{\"tags\":[\"x\",3]},\"tagsEmpty\":{\"tags\":[]},\"badTypeGoodTags\":{\"type\":7,\"tags\":[\"doc\"]},\"emptyStr\":\"\",\"star\":\"a*b?c\\\\d\",\"glob\":\"abcabd\",\"longish\":\"aaaaaaaaab\",\"u\":\"u1\",\"g\":\"g3\",\"orphan\":\"zz\"}},\"subject\":{\"id\":\"u1\",\"group\":\"g1\",\"groups\":[\"g2\",\"nope\"],\"badgroups\":[1,2],\"roles\":[\"r1\",\"r2\"],\"num\":5,\"str5\":\"5\"},\"env\":{\"graph\":{\"u1\":[\"g1\"],\"g1\":\"g2\",\"g2\":[\"g3\",5,\"g1\"],\"g3\":[],\"g4\":7,\"__proto__\":[\"gX\"],\"loop\":[\"loop\"],\"constructor\":\"g9\"},\"arr\":[1,2,3],\"str\":\"abc\",\"notmap\":[\"u1\"],\"n\":3}}","fields":["action.params.amount","action.params.amt2","action.params.name","action.params.tags","action.params.nested","action.params.nested.x.0","action.params.nested.x.2.y","action.params.nested.x.01","action.params.nested.x.3","action.params.nested.x.-1","action.params.nested.x.a","action.params.nested.x.1e0","action.params.amount.x","action.params.nul","action.params.nul.x","action.params.missing","action.params.__proto__","action.params.constructor","action.params.s","action.params.astral","action.params.bmp","action.params.lone","action.params.lone2","action.params.zero","action.params.negz","action.params.neg","action.params.inf","action.params.t","action.params.f","action.params.doc","action.params.objNoType","action.params.objBadType","action.params.objTagsNotArr","action.params.typeOnly","action.params.typeDoc2","action.params.tagsOnly","action.params.tagsEmpty","action.params.badTypeGoodTags","action.params.emptyStr","action.params.star","action.params.glob","action.params.longish","action.params","action.verb","action.resource","subject.id","subject.group","subject.num","subject.str5","subject","env.arr.2","env.arr.3","env.str","env","foo","foo.bar","","action..verb","subject.id.","action.params.u","action.params.g","action.params.orphan"],"ops":["eq","ne","in","nin","lt","lte","gt","gte","prefix","like","matches","is_a","exists","member_of","bogus"],"values":"[5,5.0,6,4,-1,0,-0,1e400,\"5\",\"alice\",\"alic\",\"alicf\",\"alice2\",\"a\",\"b\",\"\",[\"a\",\"b\"],[\"alice\",\"bob\"],[5],[6,\"x\"],[],{\"y\":\"z\"},null,true,false,\"héllo\",\"h\",\"𐀀\",\"￿\",\"\\ud800\",\"doc\",\"doc::\",\"docx\",\"secret\",\"x\",\"a*\",\"a?ice\",\"*e\",\"al*e\",\"a\\\\*b\\\\?c\\\\\\\\d\",\"a*b?c\\\\d\",\"abc*abd\",\"*ab?\",\"*a*a*b\",\"\\\\\",\"a\\\\\",\"**\",\"??????\",\"al.ce\",\"^al\",\"al(i|x)ce\",\"[a-c]lice\",\".*\",\"(a+)+\",\"g3\",\"g1\",\"g2\",\"gX\",\"g9\",[\"g3\"],[\"nope\",\"g2\"],[1,2],\"loop\"]","refs":["action.params.amount","action.params.name","action.params.tags","subject.num","subject.str5","subject.groups","subject.badgroups","action.params.missing","foo","action.params.nul","action.params.u"],"collections":["env.graph","env.notmap","env.str","env.missing","","foo"],"memFields":["subject.id","subject.group","action.params.u","action.params.g","action.params.orphan","action.params.amount","foo","action.params.__proto__"],"memTargets":"[\"g1\",\"g2\",\"g3\",\"gX\",\"g9\",\"u1\",[\"nope\",\"g3\"],[\"nope\"],[1,2],[],5,null,\"loop\",\"zz\"]","leaf":"ttf61tfftf3uuffufft61fttft3uuttu17fftffu38f3u3fuuffu21ttfttu38t3u3tuuttu5fftf4u56fuufu8t3f4u56tuutu8f3t4u56fuufu8ttft4u56tuutu308t24ft50u150ttf61tfftf3uuffufft61fttft3uuttu17fftffu38f3u3fuuffu21ttfttu38t3u3tuuttu5fftf4u56fuufu8t3f4u56tuutu8f3t4u56fuufu8ttft4u56tuutu308t24ft50u150f9tf54tf5uuffut9ft54ft5uuttu17ftf3u38f3u3fuuffu21tft3u38t3u3tuuttu13f3ttftfu9t4ut5f19t5u3tufuufu5tu9ftfttftfu9t4ut5f19t5u3tutuufu5tu9tftfftftu9f4uf5t19f5u3fufuutu5fu9t3fftftu9f4uf5t19f5u3futuutu5fu9fttfftftu9f34u3futuufu5fu9ftf6u9f10t4f5uutf12u3futuufu5fu9ftf6u9f12uf4u6tft3uf5u3futuufu5fu9ftf5u10f34u3futuufu5fut24ft50u150f16tf48tf4uuffut16ft48ft4uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu605t24ft50u150f70uuffut70uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu605t24ft50u150f70uuffut70uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu5f7u56fuufu8f7u56fuufu8t7u56tuutu8t7u56tuutu308t24ft50u150f70uuffut70uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu13f8u9ffttuf29u3fufuufu5fu9f8u9ffttuf29u3fufuufu5fu9t8u9ttffut29u3tutuutu5tu9t8u9ttffut29u3tutuutu5tu9f7tu9f34u3fufuufu5fu9f8u9f19uutf12u3fufuufu5fu9f8u9f12uf4u6f4tuf5u3fufuufu5fu9f7u10f34u3fufuufu5fut24ft50u1050f24tf50u1050f24tf50u1050f24tf50u1050f24tf50u1050f24tf50u1050f24tf50u150f22tf47uutfut22ft47uuftu17f5u38f3u3fuuffu21t5u38t3u3tuuttu605t24ft50u1050f24tf50u1050f24tf50u1050f24tf50u1050f24tf50u150f25tf44uuffut25ft44uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu13f8u9ffttuf3ttf24u3tufuufu5tu9f8u9tfttuf3ttf24u3tufuufu5tu9t8u9ftffut3fft24u3futuutu5fu9t8u9ttffut3fft24u3futuutu5fu9f7tu9ttf32u3fufuufu5fu9f8u9tf18uutf12u3fufuufu5fu9f8u9tf11uf4u6f4tuf5u3fufuufu5fu9f7u10tf33u3fufuufu5fut24ft50u150f27tf42uuffut27ft42uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu13f8u9f4uf29u3fufuufu5fu9f8u9fftfuf29u3fufuufu5fu9t8u9ttftut29u3tutuutu5tu9t8u9t4ut29u3tutuutu5tu9f7tu9fftftf29u3fufuufu5fu9f8u9fftf16uutf12u3fufuufu5fu9f8u9fftf9uf4u6f4tuf5u3fufuufu5fu9f7u10fftf31u3fufuufu5fut24ft50u150f28tf41uuffut28ft41uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu13f8u9fftfuf29u3fufuufu5fu9f8u9ffttuf29u3fufuufu5fu9t8u9ttffut29u3tutuutu5tu9t8u9ttftut29u3tutuutu5tu9f7tu9f3tf30u3fufuufu5fu9f8u9f3tf15uutf12u3fufuufu5fu9f8u9f3tf8uf4u6f4tuf5u3fufuufu5fu9f7u10f3tf30u3fufuufu5fut24ft50u150f29tf40uuffut29ft40uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu313f7tu9f4tf29u3fufuufu5fu9f8u9f4tf14uutf12u3fufuufu5fu9f8u9f4tf7uf4u6f4tuf5u3fufuufu5fu9f7u10f4tf29u3fufuufu5fut24ft50u150f70uuffut70uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu313f7tu9f34u3fufuufu5fu9f8u9f19uutf12u3fufuufu5fu9f8u9f12uf4u6f4tuf5u3fufuufu5fu9f7u10f34u3fufuufu5fut24ft50u150f5ttf63uuffut5fft63uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu5t4f3u56tuutu8t4fttu56tuutu8f4tffu56fuufu8f4t3u56fuufu308t24ft50u150f5ttf63uuffut5fft63uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu5t4f3u56tuutu8t4fttu56tuutu8f4tffu56fuufu8f4t3u56fuufu308t24ft50u150f4tf65uuffut4ft65uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu5t4fttu56tuutu8t7u56tuutu8f7u56fuufu8f4tffu56fuufu308t24ft50u150f70uuffut70uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu605t24ft50u150f23tf46uuffut23ft46uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu605t24ft50u150f24tf45uuffut24ft45uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu605t24ft50u150f70uuffut70uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu538f7u10f5tffttf24u3fufuufu5fut24ft50u150f70uuffut70uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu605t24ft50u150f70uuffut70uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu605t24ft50u150f70uuffut70uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu605t24ft50u150f70uuffut70uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu538f7u10f5tf28u3fufuufu5fut24ft50u150f70uuffut70uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu538f7u10f7tf26u3fufuufu5fut24ft50u150f70uuffut70uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu538f7u10f9tf24u3fufuufu5fut24ft50u150f70uuffut70uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu538f7u10f34u3fufuufu5fut24ft50u150f70uuffut70uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu538f7u10f5tf28u3fufuufu5fut24ft50u150f15tf54uuffut15ft54uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu13t7fu9t4ut29u3tutuutu5tu9t8u9t4ut29u3tutuutu5tu9f8u9f4uf29u3fufuufu5fu9f7tu9f4uf29u3fufuufu5fu9f7tu9f34u3fufuufu5fu9f7tu9f19uutf12u3fufuufu5fu9f7tu9f10tfuf4u6f4tuf5u3fufuufu5fu9f7u10f34u3fufuufu5fut24ft50u150f40tf29uuffut40ft29uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu13ft4ftfu9t4ut5ftfttftf3tfftftf3t5u3tutuufu5tu9ft4ftfu9t4ut5ftft4f3tfftftf3t5u3tutuufu5tu9tf4tftu9f4uf5tftf4t3fttftft3f5u3fufuutu5fu9tf4tftu9f4uf5tftfftft3fttftft3f5u3fufuutu5fu9f5tftu9f10tf4tf18u3fufuufu5fu9f8u9f10tf3tf4uutf12u3fufuufu5fu9f8u9f12uftffu6f4tuf5u3fufuufu5fu9f7u10f15tf18u3fufuufu5fut24ft50u150f70uuffut70uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu13ft4ftfu9t4ut5f3tf9tftf3t5u3tutuufu5tu9ft4ftfu9t4ut5f3tf9tftf3t5u3tutuufu5tu9tf4tftu9f4uf5t3ft9ftft3f5u3fufuutu5fu9tf4tftu9f4uf5t3ft9ftft3f5u3fufuutu5fu9f5tftu9f34u3fufuufu5fu9f8u9f10tf5ttfuuttf11u3fufuufu5fu9f8u9f12uf3tu6f4tuf5u3fufuufu5fu9f7u10f34u3fufuufu5fut24ft50u150f70uuffut70uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu13ft4ftfu9t4ut5f3tfftf6tftf3t5u3tutuufu5tu9ft4ftfu9t4ut5f3tfftf6tftf3t5u3tutuufu5tu9tf4tftu9f4uf5t3fttft6ftft3f5u3fufuutu5fu9tf4tftu9f4uf5t3fttft6ftft3f5u3fufuutu5fu9f5tftu9f34u3fufuufu5fu9f8u9f10tf7tuutf12u3fufuufu5fu9f8u9f12uf4u6f4tuf5u3fufuufu5fu9f7u10f34u3fufuufu5fut24ft50u150f70uuffut70uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu538f5ttu10f34u3fufuufu5fut24ft50u150f70uuffut70uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu13f8u9ffttuf3ttf24u3fufuufu5tu9f8u9ffttuf3ttf24u3fufuufu5tu9t8u9ttffut3fft24u3tutuutu5fu9t8u9ttffut3fft24u3tutuutu5fu9f7tu9f34u3fufuufu5fu9f8u9f19uutf12u3fufuufu5fu9f8u9f12uf4u6f4tuf5u3fufuufu5fu9f7u10f34u3fufuufu5fut24ft50u150f70uuffut70uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu13t7fu9t4ut7ft4ffttft5fft5u3tutuutu5tu9t7fu9t4ut7ft4ffttft5fft5u3tutuutu5tu9f7tu9f4uf7tf4ttfftf5ttf5u3fufuufu5fu9f7tu9f4uf7tf4ttfftf5ttf5u3fufuufu5fu9f7tu9f34u3fufuufu5fu9f8u9f19uutf12u3fufuufu5fu9f8u9f12uf4u6f4tuf5u3fufuufu5fu9f7u10f34u3fufuufu5fut24ft50u150f70uuftut70uutfu17f5u38f3u3fuuffu21t5u38t3u3tuuttu13f8u9ffttuf4tf24u3fufuufu5fu9f8u9ffttuf4tf24u3fufuufu5tu9t8u9ttffut4ft24u3tutuutu5fu9t8u9ttffut4ft24u3tutuutu5tu9f7tu9f34u3fufuufu5tu9f8u9f19uutf12u3fufuufu5tu9f8u9f12uf4u6f4tuf5u3fufuufu5tu9f7u10f34u3fufuufu5tut24ft50u150f55tf14uuffut55ft14uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu13f8u9t4uf3ttf19tft3u3tufuufu5tu9f8u9t4uf3ttf19t5u3tufuufu5tu9t8u9f4ut3fft19f5u3futuutu5fu9t8u9f4ut3fft19ftf3u3futuutu5fu9f7tu9f30tf3u3fufuufu5fu9f8u9f19uutf8tf3u3fufuufu5fu9f8u9f12uf4u6f4tuftf3u3fufuufu5fu9f7u10f30tf3u3fufuufu5fut24ft50u150ttf61tfftf3uuffufft61fttft3uuttu17fftffu38f3u3fuuffu21ttfttu38t3u3tuuttu5fftf4u56fuufu8t3f4u56tuutu8f3t4u56fuufu8ttft4u56tuutu308t24ft50u150f8tf58tffuuffut8ft58fttuuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu13ft6fu9t4ut7ft4ffttft5fft5u3tutuufu5tu9t7fu9t4ut7ft4ffttft5fft5u3tutuutu5tu9f7tu9f4uf7tf4ttfftf5ttf5u3fufuufu5fu9tf6tu9f4uf7tf4ttfftf5ttf5u3fufuutu5fu9tf6tu9f34u3fufuutu5fu9tf7u9f19uutf12u3fufuutu5fu9tf7u9f12uf4u6f4tuf5u3fufuutu5fu9tf6u10f34u3fufuutu5fut24ft50u150f70uuffut70uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu605t24ft50u150f70uuffut70uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu5t4f3u56tuutu8t4f3u56tuutu8f4t3u56fuufu8f4t3u56fuufu308t24ft50u1050f24tf50u150f70uuffut70uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu13ft4ftfu9t4ut5f3tfftf6tftf3t5u3tutuufu5tu9ft4ftfu9t4ut5f3tfftf6tftf3t5u3tutuufu5tu9tf4tftu9f4uf5t3fttft6ftft3f5u3fufuutu5fu9tf4tftu9f4uf5t3fttft6ftft3f5u3fufuutu5fu9f5tftu9f34u3fufuufu5fu9f8u9f10tf6tfuutf12u3fufuufu5fu9f8u9f12uf4u6f4tuf5u3fufuufu5fu9f7u10f34u3fufuufu5fut24ft50u150f70uuffut70uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu605t24ft50u1050f24tf50u1050f24tf50u2175f24tf50u1050f24tf50u150f70uuftut70uutfu17f5u38f3u3fuuffu21t5u38t3u3tuuttu13f8u9ffttuf4tf24u3fufuufu5fu9f8u9ffttuf4tf24u3fufuufu5tu9t8u9ttffut4ft24u3tutuutu5fu9t8u9ttffut4ft24u3tutuutu5tu9f7tu9f34u3fufuufu5tu9f8u9f19uutf12u3fufuufu5tu9f8u9f12uf4u6f4tuf5u3fufuufu5tu9f7u10f34u3fufuufu5tut24ft50u150f54tf15uuffut54ft15uuttu17f5u38tffu3fuuffu21t5u38fttu3tuuttu13f8u9t4uf3ttf22ttu3tufuufu5tu9f8u9t4uf3ttf19tffttu3tufuufu5tu9t8u9f4ut3fft19fttffu3futuutu5fu9t8u9f4ut3fft22ffu3futuutu5fu9f7tu9f29tf4u3fufuufu5fu9f8u9f19uutf7tf4u3fufuufu5fu9f8u9f12uf4u6f4tutf4u3fufuufu5fu9f7u10f29tf4u3fufuufu5fut24ft50u150f70uuffut70uuttu17f5u38f3u3fuuffu21t5u38t3u3tuuttu13f8u9ffttuf29u3fufuufu5fu9f8u9ffttuf29u3fufuufu5fu9t8u9ttffut29u3tutuutu5tu9t8u9ttffut29u3tutuutu5tu9f7tu9f34u3fufuufu5fu9f8u9f19uutf12u3fufuufu5fu9f8u9f12uf4u6f4tuf5u3fufuufu5fu9f7u10f34u3fufuufu5fut24ft50u150","mem":"t3ffttfu4ffuffuftu4tu137t3f3tfu4ffuffuftu4fu137t3ffttfu4ffuffuftu4tu137fftf3tfu4ffuffuffu4fu137f8u4ftuffuffu4fu623","leaves":"[{\"field\":\"action.params.amount\",\"op\":\"eq\",\"value\":5},{\"field\":\"action.params.amount\",\"op\":\"eq\",\"value\":6},{\"field\":\"action.params.missing\",\"op\":\"eq\",\"value\":5},null,5,[],\"x\",{},{\"field\":\"action.params.amount\",\"op\":\"bogus\",\"value\":5}]","groups":"tfu7tfu7f9ufu8fu8fu8fu8fu8fu8fu7tfuf3ufuf9ufuf3ufu7tfu7t10fu7tu8tu8tu8tu8tu8tu8tu8t13futuut4uutu8ft3ffu23t3fft4ftft3fuuf3tftf3tftf3tutu4fu13","verbs":"[\"read\",\"*\",\"write\",[\"write\",\"read\"],[\"write\",\"*\"],[\"write\"],[],[5,\"read\"],[5],5,null,\"<absent>\",\"Read\",\"\"]","resources":"[\"<absent>\",\"*\",\"/acct/1/items/2\",\"/acct/1/items/3\",\"/acct/*\",\"/acct/1/items/2*\",\"/acct/1/items/2/*\",\"/acct/2*\",\"*x\",\"\",5,null,\"re:/acct/\\\\d+/items/\\\\d+\",\"re:/acct/\\\\d+\",\"re:/acct/(a+)+\",\"re:\",\"re:.*\",\"re:/acct/1/items/[0-9]\",\"re:[\",\"re:/ACCT.*\"]","wheres":"[\"<absent>\",[],[{\"field\":\"action.params.amount\",\"op\":\"eq\",\"value\":5}],[{\"field\":\"action.params.amount\",\"op\":\"eq\",\"value\":6}],[{\"field\":\"action.params.missing\",\"op\":\"eq\",\"value\":5}],[{\"field\":\"action.params.amount\",\"op\":\"eq\",\"value\":5},{\"field\":\"action.params.amount\",\"op\":\"eq\",\"value\":6}],[{\"field\":\"action.params.amount\",\"op\":\"eq\",\"value\":5},{\"field\":\"action.params.amount\",\"op\":\"eq\",\"value\":5}],5,null,{},[null],[{\"not\":{\"field\":\"action.params.amount\",\"op\":\"eq\",\"value\":6}}],[{\"not\":{\"field\":\"action.params.missing\",\"op\":\"eq\",\"value\":5}}]]","preds":"[null,5,{},[],[{\"verb\":\"write\"}],[{\"verb\":\"write\"},{\"verb\":\"read\"}],[{\"verb\":\"read\"},{\"verb\":\"write\"}],[null,{\"verb\":\"read\"}],[{\"verb\":\"read\",\"where\":[{\"field\":\"action.params.amount\",\"op\":\"eq\",\"value\":6}]},{\"verb\":\"read\",\"resource\":\"/acct/*\"}],[{\"verb\":\"read\",\"where\":[{\"field\":\"action.params.amount\",\"op\":\"eq\",\"value\":6}]}],[\"x\"]]","predsOut":"y3nyyn6yn3yynny3nyyn6yn3yyn22y3nyyn6yn3yynny3nyyn6yn3yyn42y3nyyn6yn3yyn122y3ny3ny3n13y3n17y3n16y4nn","ctxVariants":"[{\"action\":{\"verb\":\"read\",\"resource\":\"/acct/1/items/2\"}},{\"action\":{\"verb\":\"read\"}},{\"action\":{\"resource\":\"/x\"}},{\"action\":{\"verb\":5,\"resource\":\"/x\"}},{\"action\":{\"verb\":\"read\",\"resource\":5}},{},{\"action\":null},{\"action\":{\"verb\":\"read\",\"resource\":\"/acct/1/items/2\",\"params\":5}},{\"action\":{\"verb\":\"read\",\"resource\":\"/acct/1/items/2\",\"params\":[1,2]}},{\"action\":{\"verb\":\"read\",\"resource\":\"/acct/1/items/2\",\"params\":null}},{\"action\":{\"verb\":\"read\",\"resource\":\"/acct/1/items/2\",\"params\":\"s\"}},{\"action\":{\"verb\":\"read\",\"resource\":\"𐀀/￿\"}}]","ctxConds":"[{\"field\":\"action.params\",\"op\":\"exists\"},{\"field\":\"action.params\",\"op\":\"exists\",\"value\":false},{\"field\":\"action.params.x\",\"op\":\"exists\",\"value\":false},{\"field\":\"action.params.0\",\"op\":\"exists\"},{\"field\":\"action.verb\",\"op\":\"eq\",\"ref\":\"action.params.0\"},{\"field\":\"action.verb\",\"op\":\"eq\",\"ref\":\"action.params\"},{\"field\":\"action.params.1\",\"op\":\"eq\",\"value\":2},{\"field\":\"action.verb\",\"op\":\"exists\"},{\"field\":\"action.verb\",\"op\":\"nin\",\"ref\":\"action.params\"},{\"field\":\"action.verb\",\"op\":\"exists\",\"value\":\"no\"},{\"field\":\"action.verb\",\"op\":\"exists\",\"value\":true},{\"field\":\"action.nope\",\"op\":\"exists\",\"value\":false},{\"field\":5,\"op\":\"exists\"},{\"field\":\"action.verb\",\"op\":5,\"value\":\"read\"}]","ctxv":"u7tut3uuyyn5u7tut3uun7u7fufftuun7u7tut3uun7u7tut3uun7u7fufftuun7u7fufftuun7u7tut3uuyyn5tfttfft6uuyyn5u7tut3uuyyn5u7tut3uuyyn5u7tut3uuyny5"}`

func killFParse(t *testing.T, text string) any {
	t.Helper()
	v, err := ParseJSONLenient([]byte(text))
	if err != nil {
		t.Fatalf("parse %q: %v", text, err)
	}
	return v
}

func killFTri(x int) byte {
	switch x {
	case triTrue:
		return 't'
	case triFalse:
		return 'f'
	}
	return 'u'
}

func killFStrs(v any) []string {
	out := []string{}
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

// killFCheck compares a verdict string against the reference one, naming every differing case.
func killFCheck(t *testing.T, what string, got []byte, want string, label func(i int) string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: %d cases, reference has %d", what, len(got), len(want))
	}
	bad := 0
	for i := range got {
		if got[i] != want[i] {
			bad++
			if bad <= 40 {
				t.Errorf("%s case %d %s: got %c, reference %c", what, i, label(i), got[i], want[i])
			}
		}
	}
	if bad > 40 {
		t.Errorf("%s: %d differing cases in total", what, bad)
	}
}

func TestKillFLeafDifferential(t *testing.T) {
	spec := killFParse(t, killFLeafSpec).(map[string]any)
	ctx := killFParse(t, spec["ctxText"].(string)).(map[string]any)
	fields, ops, refs := killFStrs(spec["fields"]), killFStrs(spec["ops"]), killFStrs(spec["refs"])
	values := killFParse(t, spec["values"].(string)).([]any)
	var got []byte
	var labels []string
	for _, f := range fields {
		for _, op := range ops {
			for vi, v := range values {
				got = append(got, killFTri(evaluateConditionTri(map[string]any{"field": f, "op": op, "value": v}, ctx, &regexBudget{})))
				labels = append(labels, f+" "+op+" value#"+itoa(vi))
			}
			for _, r := range refs {
				got = append(got, killFTri(evaluateConditionTri(map[string]any{"field": f, "op": op, "ref": r}, ctx, &regexBudget{})))
				labels = append(labels, f+" "+op+" ref "+r)
			}
			got = append(got, killFTri(evaluateConditionTri(map[string]any{"field": f, "op": op}, ctx, &regexBudget{})))
			labels = append(labels, f+" "+op+" (no operand)")
		}
	}
	killFCheck(t, "leaf", got, killFRLE(spec["leaf"].(string)), func(i int) string { return labels[i] })

	memFields, colls := killFStrs(spec["memFields"]), killFStrs(spec["collections"])
	targets := killFParse(t, spec["memTargets"].(string)).([]any)
	got, labels = nil, nil
	for _, f := range memFields {
		for _, c := range colls {
			for vi, v := range targets {
				got = append(got, killFTri(evaluateConditionTri(map[string]any{"field": f, "op": "member_of", "collection": c, "value": v}, ctx, &regexBudget{})))
				labels = append(labels, f+" in "+c+" target#"+itoa(vi))
			}
			for _, r := range refs {
				got = append(got, killFTri(evaluateConditionTri(map[string]any{"field": f, "op": "member_of", "collection": c, "ref": r}, ctx, &regexBudget{})))
				labels = append(labels, f+" in "+c+" ref "+r)
			}
			got = append(got, killFTri(evaluateConditionTri(map[string]any{"field": f, "op": "member_of", "collection": c}, ctx, &regexBudget{})))
			labels = append(labels, f+" in "+c+" (no operand)")
			got = append(got, killFTri(evaluateConditionTri(map[string]any{"field": f, "op": "member_of", "collection": jnum(5), "value": "g1"}, ctx, &regexBudget{})))
			labels = append(labels, f+" collection=5")
		}
	}
	killFCheck(t, "member_of", got, killFRLE(spec["mem"].(string)), func(i int) string { return labels[i] })
}

// killFRLE expands the run-length encoded verdict strings of the spec ("u37" = 37 x 'u').
func killFRLE(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); {
		c := s[i]
		i++
		n := 0
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			n = n*10 + int(s[i]-'0')
			i++
		}
		if n == 0 {
			n = 1
		}
		sb.WriteString(strings.Repeat(string(c), n))
	}
	return sb.String()
}

func killFBit(b bool) byte {
	if b {
		return 'y'
	}
	return 'n'
}

const killFAbsent = "<absent>"

// Boolean groupings, predicateMatches (verb / resource / where) and evaluatePredicates, and the context-shape variants
// (params unavailable, action without verb/resource, astral resources). The case lists are rebuilt here in exactly
// the order the generator used.
func TestKillFGroupsAndPredicates(t *testing.T) {
	spec := killFParse(t, killFLeafSpec).(map[string]any)
	ctx := killFParse(t, spec["ctxText"].(string)).(map[string]any)
	leaves := killFParse(t, spec["leaves"].(string)).([]any)
	var got []byte
	var labels []string
	tri := func(x any) {
		got = append(got, killFTri(evaluateConditionTri(x, ctx, &regexBudget{})))
		s, _ := canonicalLenient(x)
		labels = append(labels, s)
	}
	for _, k := range []string{"all_of", "any_of"} {
		for _, a := range leaves {
			tri(map[string]any{k: []any{a}})
		}
		for _, a := range leaves {
			for _, b := range leaves {
				tri(map[string]any{k: []any{a, b}})
			}
		}
		for _, a := range leaves[:3] {
			for _, b := range leaves[:3] {
				for _, c := range leaves[:3] {
					tri(map[string]any{k: []any{a, b, c}})
				}
			}
		}
		for _, bad := range []any{[]any{}, jnum(5), nil, map[string]any{}, "x", true} {
			tri(map[string]any{k: bad})
		}
	}
	for _, a := range leaves {
		tri(map[string]any{"not": a})
		tri(map[string]any{"not": map[string]any{"not": a}})
		tri(a)
	}
	tri(map[string]any{"not": nil})
	tri(map[string]any{"not": []any{}})
	for _, a := range leaves[:3] {
		for _, b := range leaves[:3] {
			tri(map[string]any{"all_of": []any{a}, "any_of": []any{b}})
			tri(map[string]any{"any_of": []any{a}, "not": b})
			tri(map[string]any{"all_of": []any{a}, "not": b})
			tri(map[string]any{"not": a, "field": "action.params.amount", "op": "eq", "value": jnum(5)})
			tri(map[string]any{"all_of": []any{map[string]any{"any_of": []any{a, b}}, map[string]any{"not": b}}})
			tri(map[string]any{"any_of": []any{map[string]any{"all_of": []any{a, b}}, map[string]any{"not": a}}})
		}
	}
	killFCheck(t, "groups", got, killFRLE(spec["groups"].(string)), func(i int) string { return labels[i] })

	verbs := killFParse(t, spec["verbs"].(string)).([]any)
	resources := killFParse(t, spec["resources"].(string)).([]any)
	wheres := killFParse(t, spec["wheres"].(string)).([]any)
	mk := func(v, r, w any) map[string]any {
		p := map[string]any{}
		for k, x := range map[string]any{"verb": v, "resource": r, "where": w} {
			if s, ok := x.(string); !ok || s != killFAbsent {
				p[k] = x
			}
		}
		return p
	}
	got, labels = nil, nil
	pm := func(p any) {
		got = append(got, killFBit(predicateMatches(p, ctx, &regexBudget{})))
		s, _ := canonicalLenient(p)
		labels = append(labels, "predicateMatches "+s)
	}
	for _, v := range verbs {
		for _, r := range resources {
			pm(mk(v, r, killFAbsent))
		}
	}
	for _, w := range wheres {
		for _, r := range []any{killFAbsent, "/acct/*", "re:/acct/.*", "x"} {
			pm(mk("read", r, w))
		}
	}
	for _, p := range []any{nil, jnum(5), []any{}, "read", map[string]any{"resource": "*"}, map[string]any{}} {
		pm(p)
	}
	for _, p := range killFParse(t, spec["preds"].(string)).([]any) {
		got = append(got, killFBit(evaluatePredicates(p, ctx)))
		s, _ := canonicalLenient(p)
		labels = append(labels, "evaluatePredicates "+s)
	}
	killFCheck(t, "predicates", got, killFRLE(spec["predsOut"].(string)), func(i int) string { return labels[i] })

	cvs := killFParse(t, spec["ctxVariants"].(string)).([]any)
	conds := killFParse(t, spec["ctxConds"].(string)).([]any)
	got, labels = nil, nil
	for ci, cv := range cvs {
		c := cv.(map[string]any)
		for xi, x := range conds {
			got = append(got, killFTri(evaluateConditionTri(x, c, &regexBudget{})))
			labels = append(labels, "ctx#"+itoa(ci)+" cond#"+itoa(xi))
		}
		for _, r := range []string{"*", "/acct/1/items/2", "\U00010000*", "\xed\xa0\x80*", "\U00010000/￿", "re:\U00010000/.", "re:../."} {
			got = append(got, killFBit(predicateMatches(map[string]any{"verb": "read", "resource": r}, c, &regexBudget{})))
			labels = append(labels, "ctx#"+itoa(ci)+" resource "+r)
		}
	}
	killFCheck(t, "ctx variants", got, killFRLE(spec["ctxv"].(string)), func(i int) string { return labels[i] })
}

// Length caps (UTF-16 code units, as in JavaScript), the per-document regex budget and the member_of closure cap, at
// the exact boundaries; every expectation was computed with the TS reference.
func TestKillFBoundaries(t *testing.T) {
	A := func(n int, c string) string { return strings.Repeat(c, n) }
	const astral = "\U00010000"
	ctxS := func(s string) map[string]any {
		return map[string]any{"action": map[string]any{"verb": "read", "resource": "/r", "params": map[string]any{"s": s}}}
	}
	leaf := func(op, s, p string) byte {
		return killFTri(evaluateConditionTri(map[string]any{"field": "action.params.s", "op": op, "value": p}, ctxS(s), &regexBudget{}))
	}
	for _, c := range []struct {
		name     string
		op, s, p string
		want     byte
	}{
		{"like pattern 512", "like", A(512, "a"), A(511, "a") + "*", 't'},
		{"like pattern 513", "like", A(512, "a"), A(512, "a") + "*", 'u'},
		{"like subject 512", "like", A(512, "a"), "*", 't'},
		{"like subject 513", "like", A(513, "a"), "*", 'u'},
		{"like astral subject 256", "like", A(256, astral), "*", 't'},
		{"like astral subject 257", "like", A(257, astral), "*", 'u'},
		{"like astral pattern 256", "like", "x", A(256, astral), 'f'},
		{"like astral pattern 257", "like", "x", A(257, astral), 'u'},
		{"matches pattern 200", "matches", A(200, "a"), A(200, "a"), 't'},
		{"matches pattern 201", "matches", A(201, "a"), A(201, "a"), 'u'},
		{"matches subject 512", "matches", A(512, "a"), "a*", 't'},
		{"matches subject 513", "matches", A(513, "a"), "a*", 'u'},
		{"matches astral subject 256", "matches", A(256, astral), ".*", 't'},
		{"matches astral subject 257", "matches", A(257, astral), ".*", 'u'},
		{"matches unsafe", "matches", "aa", "(a+)+", 'u'},
		{"matches malformed", "matches", "aa", "(", 'u'},
	} {
		if got := leaf(c.op, c.s, c.p); got != c.want {
			t.Errorf("%s: got %c, reference %c", c.name, got, c.want)
		}
	}
	pr := func(resource, p string) bool {
		return evaluatePredicates([]any{map[string]any{"verb": "read", "resource": p}}, map[string]any{"action": map[string]any{"verb": "read", "resource": resource}})
	}
	for _, c := range []struct {
		name        string
		resource, p string
		want        bool
	}{
		{"re: source 200", A(200, "a"), "re:" + A(200, "a"), true},
		{"re: source 201", A(201, "a"), "re:" + A(201, "a"), false},
		{"re: resource 512", A(512, "a"), "re:a*", true},
		{"re: resource 513", A(513, "a"), "re:a*", false},
		{"re: astral resource 256", A(256, astral), "re:.*", true},
		{"re: astral resource 257", A(257, astral), "re:.*", false},
		{"re: astral source 100", A(100, astral), "re:" + A(100, astral), true},
		{"re: astral source 101", A(101, astral), "re:" + A(101, astral), false},
		{"prefix glob splits a surrogate pair", astral + "x", "\xed\xa0\x80*", true},
	} {
		if got := pr(c.resource, c.p); got != c.want {
			t.Errorf("%s: got %v, reference %v", c.name, got, c.want)
		}
	}
	// one document regex budget: 64 evaluations, 8192 source chars, 5e6 steps
	bp := func(n int, resource, s, p string) bool {
		where := []any{}
		for i := 0; i < n; i++ {
			where = append(where, map[string]any{"field": "action.params.s", "op": "matches", "value": p})
		}
		return evaluatePredicates([]any{map[string]any{"verb": "read", "resource": resource, "where": where}}, ctxS(s))
	}
	for _, c := range []struct {
		name           string
		n              int
		resource, s, p string
		want           bool
	}{
		{"64 evaluations", 64, "*", "aaa", "a*", true},
		{"65 evaluations", 65, "*", "aaa", "a*", false},
		{"63 + re: resource", 63, "re:.*", "aaa", "a*", true},
		{"64 + re: resource", 64, "re:.*", "aaa", "a*", false},
		{"40 x 200 source chars", 40, "*", A(200, "a"), A(200, "a"), true},
		{"41 x 200 source chars", 41, "*", A(200, "a"), A(200, "a"), false},
		{"53 x steps", 53, "*", A(512, "a"), A(150, "a") + ".*", true},
		{"54 x steps", 54, "*", A(512, "a"), A(150, "a") + ".*", false},
	} {
		if got := bp(c.n, c.resource, c.s, c.p); got != c.want {
			t.Errorf("budget %s: got %v, reference %v", c.name, got, c.want)
		}
	}
	// the budget spans every predicate of one evaluatePredicates call
	many := func(n int) bool {
		ps := []any{}
		for i := 0; i < n; i++ {
			ps = append(ps, map[string]any{"verb": "read", "where": []any{map[string]any{"field": "action.params.s", "op": "matches", "value": "b"}}})
		}
		ps = append(ps, map[string]any{"verb": "read", "where": []any{map[string]any{"field": "action.params.s", "op": "matches", "value": "a*"}}})
		return evaluatePredicates(ps, ctxS("aaa"))
	}
	if !many(63) || many(64) {
		t.Errorf("document budget across predicates: 63 -> %v (want true), 64 -> %v (want false)", many(63), many(64))
	}
	// member_of closure: at most 10000 nodes are expanded
	g := map[string]any{}
	for i := 0; i < 10002; i++ {
		g["n"+itoa(i)] = []any{"n" + itoa(i+1)}
	}
	mc := func(target string) byte {
		ctx := map[string]any{"action": map[string]any{"verb": "r", "resource": "x"}, "subject": map[string]any{"id": "n0"}, "env": map[string]any{"g": g}}
		return killFTri(evaluateConditionTri(map[string]any{"field": "subject.id", "op": "member_of", "collection": "env.g", "value": target}, ctx, &regexBudget{}))
	}
	if a, b := mc("n10000"), mc("n10001"); a != 't' || b != 'f' {
		t.Errorf("closure cap: n10000 -> %c (want t), n10001 -> %c (want f)", a, b)
	}
	// a node already seen is not queued again: a duplicated edge must not spend the visit budget twice
	g = map[string]any{"m0": []any{"m1", "m1"}}
	for i := 1; i < 10003; i++ {
		g["m"+itoa(i)] = []any{"m" + itoa(i+1)}
	}
	mcd := func(target string) byte {
		ctx := map[string]any{"action": map[string]any{"verb": "r", "resource": "x"}, "subject": map[string]any{"id": "m0"}, "env": map[string]any{"g": g}}
		return killFTri(evaluateConditionTri(map[string]any{"field": "subject.id", "op": "member_of", "collection": "env.g", "value": target}, ctx, &regexBudget{}))
	}
	if a, b := mcd("m10000"), mcd("m10001"); a != 't' || b != 'f' {
		t.Errorf("closure dedupe: m10000 -> %c (want t), m10001 -> %c (want f)", a, b)
	}
}

// Edge cases the cartesian spec does not reach: a non-string / empty / null ref, a context key outside the three
// roots, a missing root, own "__proto__" / "constructor" / "prototype" keys (JSON.parse makes them own properties),
// array index 10, escaped glob characters, '?' followed by '*', and forbidden node names in a member_of graph.
// Expected verdicts from the TS reference (evaluateConditionTri), in order.
func TestKillFEdgeCases(t *testing.T) {
	ctx := killFParse(t, `{"action":{"verb":"read","resource":"/r","params":{"__proto__":{"x":1},"constructor":5,"prototype":[1],"nul":null,"arr":[0,1,2,3,4,5,6,7,8,9,10],"s":"ab","s2":"a*","s3":"abc","s4":"a","s5":"","pp":"__proto__","pc":"constructor","pq":"prototype","u":"u1"}},"subject":{"id":"u1"},"other":{"x":1}}`).(map[string]any)
	ctx["subject"].(map[string]any)["graph"] = killFParse(t, `{"__proto__":["gX"],"constructor":"gY","prototype":["gZ"],"u1":["__proto__"]}`)
	conds := killFParse(t, `[
{"field":"action.params.nul","op":"eq","ref":5},{"field":"action.params.nul","op":"eq","ref":""},{"field":"action.params.nul","op":"eq","ref":null},{"field":"action.params.nul","op":"ne","ref":true},
{"field":"other.x","op":"exists"},{"field":"other","op":"exists"},{"field":"other.x","op":"eq","value":1},
{"field":"env","op":"exists"},{"field":"env.x","op":"exists"},
{"field":"action.params.__proto__","op":"exists"},{"field":"action.params.__proto__.x","op":"exists"},{"field":"action.params.constructor","op":"exists"},{"field":"action.params.prototype","op":"exists"},{"field":"action.params.__proto__","op":"exists","value":false},
{"field":"action.params.arr.10","op":"eq","value":10},{"field":"action.params.arr.10","op":"exists"},{"field":"action.params.arr.11","op":"exists"},{"field":"action.params.arr.01","op":"exists"},{"field":"action.params.arr.00","op":"exists"},
{"field":"action.params.s","op":"like","value":"a\\*"},{"field":"action.params.s2","op":"like","value":"a\\*"},{"field":"action.params.s","op":"like","value":"\\a\\b"},
{"field":"action.params.s3","op":"like","value":"?*"},{"field":"action.params.s3","op":"like","value":"a?*"},{"field":"action.params.s4","op":"like","value":"a?*"},{"field":"action.params.s3","op":"like","value":"*?"},{"field":"action.params.s5","op":"like","value":"*?"},{"field":"action.params.s3","op":"like","value":"??*?"},{"field":"action.params.s3","op":"like","value":"?*c"},
{"field":"action.params.pp","op":"member_of","collection":"subject.graph","value":"gX"},{"field":"action.params.pc","op":"member_of","collection":"subject.graph","value":"gY"},{"field":"action.params.pq","op":"member_of","collection":"subject.graph","value":"gZ"},{"field":"action.params.u","op":"member_of","collection":"subject.graph","value":"gX"},{"field":"action.params.u","op":"member_of","collection":"subject.graph","value":"__proto__"},{"field":"action.params.pp","op":"member_of","collection":"subject.graph","value":"__proto__"}
]`).([]any)
	const want = "uuuuffufffffftttffffttttftfttfffftt"
	got := []byte{}
	for _, c := range conds {
		got = append(got, killFTri(evaluateConditionTri(c, ctx, &regexBudget{})))
	}
	killFCheck(t, "edge", got, want, func(i int) string { s, _ := canonicalLenient(conds[i]); return s })
}
