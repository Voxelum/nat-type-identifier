import stun, { convertToHexBuffer, genTransactionId } from '../index'
import { test } from 'uvu'
import assert from 'uvu/assert'


test('convert hex', () => {
    const buf = convertToHexBuffer('0003000400000006')
    const expect = Buffer.from([0, 3, 0, 4, 0, 0, 0, 6])
    assert.equal(buf.compare(expect), 0)
})

test('stun', async () => {
    const result = await stun()
    console.log(result)
})

test('transaction', () => {
    const id = genTransactionId()
    const buf = convertToHexBuffer(id)
    const slicedBuf = buf.slice(0, 16)
    console.log(id)
    console.log(buf)
    console.log(slicedBuf)
})

test.run()
