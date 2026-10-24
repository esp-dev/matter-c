#include "rgb_led.h"
#include "driver/rmt_tx.h"
#include <stdlib.h>
#include <stdio.h>
struct Matter_Lab_Led {
    rmt_channel_handle_t channel; rmt_encoder_handle_t encoder;
    uint32_t generation; uint8_t grb[3]; bool pending,enabled;
};
/* One WS2812: 10 MHz ticks, GRB, 0.3/0.9 us zero, 0.9/0.3 us one,
 * 80 us reset. All 25 symbols fit the minimum 48-symbol C6 RMT memory.
 * The ISR encoder never allocates or calls the model. */
static size_t encode(const void* data,size_t size,size_t written,size_t available,rmt_symbol_word_t* symbols,bool* done,void* user) {
    (void)user;
    if(available<8) return 0;
    size_t pos=written/8;
    if(pos<size) {
        uint8_t byte=((const uint8_t*)data)[pos];
        for(unsigned i=0;i<8;++i) {
            bool one=(byte&(0x80u>>i))!=0;
            symbols[i]=(rmt_symbol_word_t){.level0=1,.duration0=one?9:3,.level1=0,.duration1=one?3:9};
        }
        return 8;
    }
    symbols[0]=(rmt_symbol_word_t){.level0=0,.duration0=400,.level1=0,.duration1=400}; *done=true; return 1;
}
Matter_Lab_Led_T matter_lab_led_new(void) {
    Matter_Lab_Led_T s=calloc(1,sizeof(*s)); if(!s) return NULL;
    const rmt_tx_channel_config_t config={.gpio_num=8,.clk_src=RMT_CLK_SRC_DEFAULT,.resolution_hz=10000000,.mem_block_symbols=48,.trans_queue_depth=1};
    if(rmt_new_tx_channel(&config,&s->channel)!=ESP_OK) goto fail;
    const rmt_simple_encoder_config_t encoder={.callback=encode,.min_chunk_size=8};
    if(rmt_new_simple_encoder(&encoder,&s->encoder)!=ESP_OK || rmt_enable(s->channel)!=ESP_OK) goto fail;
    s->enabled=true; return s;
fail:
    (void)matter_lab_led_delete(s); return NULL;
}
bool matter_lab_led_process(Matter_Lab_Led_T s,Matter_Lab_Rgb_T light,bool* changed) {
    if(!s || !light || !changed) return false;
    *changed=false;
    if(s->pending) {
        esp_err_t r=rmt_tx_wait_all_done(s->channel,0);
        if(r==ESP_ERR_TIMEOUT) return true;
        if(r!=ESP_OK) return false;
        s->pending=false;
    }
    uint8_t rgb[3]; uint32_t generation=s->generation;
    if(!matter_lab_rgb_pixels(light,rgb,&generation)) return true;
    s->grb[0]=rgb[1]; s->grb[1]=rgb[0]; s->grb[2]=rgb[2];
    const rmt_transmit_config_t config={0};
    if(rmt_transmit(s->channel,s->encoder,s->grb,sizeof(s->grb),&config)!=ESP_OK) return false;
    s->generation=generation; s->pending=true;
    *changed=true;
    printf("RGB_QUEUED generation=%lu r=%u g=%u b=%u\n",(unsigned long)s->generation,rgb[0],rgb[1],rgb[2]);
    return true;
}
bool matter_lab_led_delete(Matter_Lab_Led_T s) {
    if(!s) return true;
    /* The app pumps to completion before teardown; never free borrowed GRB. */
    if(s->pending) {
        if(rmt_tx_wait_all_done(s->channel,0)!=ESP_OK) return false;
        s->pending=false;
    }
    if(s->enabled && rmt_disable(s->channel)!=ESP_OK) return false;
    if(s->encoder && rmt_del_encoder(s->encoder)!=ESP_OK) return false;
    if(s->channel && rmt_del_channel(s->channel)!=ESP_OK) return false;
    free(s); return true;
}
