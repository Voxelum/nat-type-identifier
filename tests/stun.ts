import { getNatInfoUDP, sampleNatType } from '../index'
import { test } from 'uvu'


test('getNatInfoUDP', async () => {
    const info = await getNatInfoUDP()
    console.log(info)
})

// test('stun', async () => {
//     const result = await sampleNatType({ stun: 'stun.xten.com' })
//     console.log(result)
// })

test.run()
